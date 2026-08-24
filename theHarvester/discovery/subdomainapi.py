from urllib.parse import urlencode

from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchSubdomainApi:
    """Collect passive hostname evidence from Subdomain API."""

    BASE_URL = 'https://api.subdomain.app/v1/query'

    def __init__(self, word: str) -> None:
        self.word = normalize_hostname(word)
        self.totalhosts: set[str] = set()
        self.proxy: bool | str = False

    async def do_search(self) -> SourceExecutionReport | None:
        url = f'{self.BASE_URL}?{urlencode({"domain": self.word})}'
        responses = await AsyncFetcher.fetch_all(
            [url],
            headers={'User-Agent': Core.get_user_agent()},
            proxy=self.proxy,
            json=True,
            include_metadata=True,
        )
        response = responses[0] if responses else None
        if error := provider_http_error(response):
            return SourceExecutionReport(*error)
        assert isinstance(response, FetcherResponse)
        payload = response.body
        if not isinstance(payload, dict):
            return SourceExecutionReport('failed', 'invalid-response')

        count = payload.get('count')
        total = payload.get('total')
        subdomains = payload.get('subdomains')
        provider_domain = payload.get('domain')
        valid_count = isinstance(count, int) and not isinstance(count, bool) and count >= 0
        valid_total = isinstance(total, int) and not isinstance(total, bool) and total >= 0
        if (
            provider_domain != self.word
            or not valid_count
            or not valid_total
            or not isinstance(subdomains, list)
            or count != len(subdomains)
            or total < count
        ):
            return SourceExecutionReport('failed', 'invalid-response')

        for candidate in subdomains:
            if not isinstance(candidate, str) or '*' in candidate:
                continue
            try:
                hostname = normalize_hostname(candidate)
            except ValueError:
                continue
            if hostname != self.word and hostname.endswith(f'.{self.word}'):
                self.totalhosts.add(hostname)
        return SourceExecutionReport('partial', 'provider-limit') if total > count else None

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool | str = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')
