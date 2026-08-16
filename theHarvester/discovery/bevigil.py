from urllib.parse import urlsplit, urlunsplit

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchBeVigil:
    def __init__(self, word: str) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.urls: set[str] = set()
        self.key = Core.bevigil_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('bevigil')
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _has_results(self) -> bool:
        return bool(self.totalhosts or self.urls)

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self._has_results() else status
        self.stop_reason = reason

    def _scoped_url(self, value: object) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = urlsplit(value.strip())
            hostname = normalize_scoped_hostname(parsed.hostname, self.word)
            port = parsed.port
        except ValueError:
            return None
        if parsed.scheme.casefold() not in {'http', 'https'} or hostname is None or parsed.username or parsed.password:
            return None
        netloc = f'{hostname}:{port}' if port is not None else hostname
        return urlunsplit((parsed.scheme.casefold(), netloc, parsed.path, parsed.query, ''))

    async def do_search(self) -> None:
        self.execution_status = None
        self.stop_reason = None
        subdomain_endpoint = f'https://osint.bevigil.com/api/{self.word}/subdomains/'
        url_endpoint = f'https://osint.bevigil.com/api/{self.word}/urls/'
        headers = {'X-Access-Token': self.key}
        requests = (
            (subdomain_endpoint, 'subdomains'),
            (url_endpoint, 'urls'),
        )

        for endpoint, field in requests:
            try:
                responses = await AsyncFetcher.fetch_all(
                    [endpoint],
                    json=True,
                    proxy=self.proxy,
                    headers=headers,
                    include_metadata=True,
                )
            except Exception:
                self._stop('failed', 'transport-error')
                return
            response = responses[0] if responses else None
            if not isinstance(response, FetcherResponse):
                self._stop('failed', 'transport-error')
                return
            if response.status in {401, 403}:
                self._stop('failed', 'access-denied')
                return
            if response.status == 429:
                self._stop('rate-limited', 'http-429')
                return
            if not 200 <= response.status < 300:
                self._stop('failed', f'http-{response.status}')
                return
            if not isinstance(response.body, dict) or not isinstance(response.body.get(field), list):
                self._stop('failed', 'invalid-response')
                return

            malformed = False
            for value in response.body[field]:
                if field == 'subdomains':
                    if not isinstance(value, str):
                        malformed = True
                    elif hostname := normalize_scoped_hostname(value, self.word):
                        self.totalhosts.add(hostname)
                elif url := self._scoped_url(value):
                    self.urls.add(url)
                elif not isinstance(value, str):
                    malformed = True
            if malformed:
                self._stop('failed', 'invalid-response')

        if self.execution_status is not None and self._has_results():
            self.execution_status = 'partial'
        elif self.execution_status is None:
            self.execution_status = 'completed'
            self.stop_reason = None if self._has_results() else 'no-results'

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_urls(self) -> set[str]:
        return self.urls

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
