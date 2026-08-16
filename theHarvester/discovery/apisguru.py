import asyncio
import re
from email.errors import HeaderParseError
from email.headerregistry import Address
from ipaddress import ip_address
from itertools import islice
from urllib.parse import unquote, urlsplit, urlunsplit

from theHarvester.lib.core import AsyncFetcher, FetcherResponse, ResponseStreamError
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport, SourceReportStatus


class SearchApisGuru:
    """Collect target-scoped API metadata from the public APIs.guru directory.

    Results include descendant hostnames, contact emails, concrete API base URLs,
    and related in-scope URLs. The adapter does not resolve IP addresses or expand
    OpenAPI paths into operation endpoints. It checks up to 1,000 matching specs
    for up to ten minutes; ``--limit`` caps stored results, not spec traversal.
    The shared fetcher caps each JSON response at 16 MiB. Oversized specs are
    skipped and leave the source marked partial.
    """

    DIRECTORY_ROOT = 'https://api.apis.guru/v2'
    MAX_DIRECTORY_ENTRIES = 1000
    MAX_SPEC_ITEMS = 1000
    MAX_RESULTS_PER_ROUTE = 1000
    MAX_URL_LENGTH = 4096
    REQUEST_TIMEOUT = 60
    MAX_RUNTIME_SECONDS = 600

    def __init__(self, word: str, limit: int) -> None:
        self.word = self._domain(word)
        requested_limit = max(0, limit)
        self.result_limit = min(requested_limit, self.MAX_RESULTS_PER_ROUTE)
        self.result_limit_is_protective = requested_limit > self.MAX_RESULTS_PER_ROUTE
        self.totalhosts: set[str] = set()
        self.totalemails: set[str] = set()
        self.urls: set[str] = set()
        self.proxy = False
        self._report: SourceExecutionReport | None = None
        self.result_limit_reached = False
        self.protective_limit_reached = False

    @staticmethod
    def _domain(value: str) -> str:
        candidate = value.strip().lower().rstrip('.')
        if not candidate.isascii():
            return ''
        labels = candidate.split('.')
        try:
            ip_address(candidate)
        except ValueError:
            pass
        else:
            return ''
        if (
            not candidate
            or len(labels) < 2
            or len(candidate) > 253
            or any(
                not label
                or len(label) > 63
                or label.startswith('-')
                or label.endswith('-')
                or re.fullmatch(r'[a-z0-9-]+', label) is None
                for label in labels
            )
        ):
            return ''
        return candidate

    def _stop(self, status: SourceReportStatus, reason: str) -> None:
        self._report = SourceExecutionReport(status, reason)

    async def _fetch(self, url: str) -> FetcherResponse | None:
        try:
            return await AsyncFetcher.fetch_json(
                url=url,
                proxy=self.proxy,
                request_timeout=self.REQUEST_TIMEOUT,
            )
        except asyncio.CancelledError:
            self._stop('failed', 'cancelled')
            raise
        except ResponseStreamError as error:
            self._stop('failed', error.reason)
            return None

    def _matches_target(self, value: object) -> bool:
        if not isinstance(value, str):
            return False
        domain = self._domain(value)
        return bool(domain and normalize_scoped_hostname(domain, self.word))

    def _retain(self, values: set[str], value: str) -> None:
        if value not in values and len(values) >= self.result_limit:
            if self.result_limit_is_protective:
                self.protective_limit_reached = True
            else:
                self.result_limit_reached = True
        else:
            values.add(value)

    def _add_host(self, value: str) -> None:
        try:
            parsed = urlsplit(f'//{value.strip()}')
            parsed.port
        except ValueError:
            return
        if parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
            return
        hostname = normalize_scoped_hostname(self._domain(parsed.hostname or ''), self.word)
        if hostname is not None and hostname != self.word:
            self._retain(self.totalhosts, hostname)

    def _add_url(self, value: object) -> None:
        if not isinstance(value, str):
            return
        if len(value) > self.MAX_URL_LENGTH or any(character.isspace() or not character.isprintable() for character in value):
            return
        try:
            parsed = urlsplit(value.strip())
            port = parsed.port
        except ValueError:
            return
        if parsed.scheme.lower() not in {'http', 'https'} or parsed.hostname is None:
            return
        if parsed.username is not None or parsed.password is not None:
            return
        hostname = normalize_scoped_hostname(self._domain(parsed.hostname), self.word)
        if hostname is None:
            return
        self._add_host(hostname)
        if '{' in value or '}' in value:
            return
        netloc = f'{hostname}:{port}' if port is not None else hostname
        normalized_url = urlunsplit((parsed.scheme.lower(), netloc, parsed.path, '', ''))
        self._retain(self.urls, normalized_url)

    def _add_email(self, value: object) -> None:
        if not isinstance(value, str) or value.count('@') != 1:
            return
        candidate = value.strip().lower()
        try:
            candidate_length = len(candidate.encode('utf-8'))
        except UnicodeEncodeError:
            return
        if candidate_length > 254:
            return
        try:
            address = Address(addr_spec=candidate)
        except (HeaderParseError, ValueError):
            return
        if len(address.username.encode('utf-8')) > 64:
            return
        normalized_domain = normalize_scoped_hostname(self._domain(address.domain), self.word)
        if address.username and normalized_domain:
            normalized_email = Address(username=address.username, domain=normalized_domain).addr_spec
            self._retain(self.totalemails, normalized_email)

    def _parse_spec(self, spec: dict) -> bool:
        malformed = not isinstance(spec.get('openapi') or spec.get('swagger'), str)
        host = spec.get('host')
        schemes = spec.get('schemes')
        base_path = spec.get('basePath')
        if 'host' in spec and not isinstance(host, str):
            malformed = True
        if 'schemes' in spec and not isinstance(schemes, list):
            malformed = True
        if 'basePath' in spec and (not isinstance(base_path, str) or not base_path.startswith('/')):
            malformed = True
        if isinstance(host, str):
            self._add_host(host)
        if isinstance(host, str) and isinstance(schemes, list):
            path = base_path if isinstance(base_path, str) and base_path.startswith('/') else ''
            if len(schemes) > self.MAX_SPEC_ITEMS:
                self.protective_limit_reached = True
            for scheme in islice(schemes, self.MAX_SPEC_ITEMS):
                if isinstance(scheme, str) and scheme.lower() in {'http', 'https'}:
                    self._add_url(f'{scheme.lower()}://{host}{path}')
                elif not isinstance(scheme, str):
                    malformed = True

        servers = spec.get('servers')
        if isinstance(servers, list):
            if len(servers) > self.MAX_SPEC_ITEMS:
                self.protective_limit_reached = True
            for server in islice(servers, self.MAX_SPEC_ITEMS):
                if not isinstance(server, dict):
                    malformed = True
                elif not isinstance(server.get('url'), str):
                    malformed = True
                else:
                    self._add_url(server.get('url'))
        elif 'servers' in spec:
            malformed = True

        info = spec.get('info')
        if isinstance(info, dict):
            contact = info.get('contact')
            if isinstance(contact, dict):
                if 'email' in contact and not isinstance(contact.get('email'), str):
                    malformed = True
                if 'url' in contact and not isinstance(contact.get('url'), str):
                    malformed = True
                self._add_email(contact.get('email'))
                self._add_url(contact.get('url'))
            elif 'contact' in info:
                malformed = True
            if 'termsOfService' in info and not isinstance(info.get('termsOfService'), str):
                malformed = True
            self._add_url(info.get('termsOfService'))
        elif 'info' in spec:
            malformed = True

        external_docs = spec.get('externalDocs')
        if isinstance(external_docs, dict):
            if 'url' in external_docs and not isinstance(external_docs.get('url'), str):
                malformed = True
            self._add_url(external_docs.get('url'))
        elif 'externalDocs' in spec:
            malformed = True
        return malformed

    @classmethod
    def _spec_url(cls, value: object) -> str | None:
        if (
            not isinstance(value, str)
            or len(value) > cls.MAX_URL_LENGTH
            or any(character.isspace() or not character.isprintable() for character in value)
        ):
            return None
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            return None
        decoded_path = unquote(parsed.path)
        if '\\' in decoded_path or any(part in {'.', '..'} for part in decoded_path.split('/')):
            return None
        if (
            parsed.scheme != 'https'
            or parsed.hostname != 'api.apis.guru'
            or port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or not decoded_path.startswith('/v2/specs/')
            or not decoded_path.endswith('.json')
            or parsed.query
            or parsed.fragment
        ):
            return None
        return value

    async def do_search(self) -> None:
        if not self.word:
            self._stop('failed', 'invalid-target')
            return
        directory_response = await self._fetch(f'{self.DIRECTORY_ROOT}/{self.word}.json')
        if directory_response is None:
            if self._report is None:
                self._stop('failed', 'transport-error')
            return
        if directory_response.status == 404:
            return
        if directory_response.status == 429:
            self._stop('rate-limited', 'http-429')
            return
        if directory_response.status in {401, 403}:
            self._stop('failed', 'access-denied')
            return
        if not 200 <= directory_response.status < 300:
            self._stop('failed', f'http-{directory_response.status}')
            return
        if not isinstance(directory_response.body, dict):
            self._stop('failed', 'invalid-response')
            return

        directory = directory_response.body.get('apis', directory_response.body)
        if not isinstance(directory, dict):
            self._stop('failed', 'invalid-response')
            return

        directory_limit_reached = len(directory) > self.MAX_DIRECTORY_ENTRIES
        spec_urls: list[str] = []
        malformed = False
        seen_spec_urls: set[str] = set()
        for api_id, api in islice(directory.items(), self.MAX_DIRECTORY_ENTRIES):
            if not isinstance(api_id, str):
                continue
            provider_domain = api_id.partition(':')[0]
            provider_matches = self._matches_target(provider_domain)
            if not isinstance(api, dict):
                malformed = provider_matches or malformed
                continue
            version = api
            if 'swaggerUrl' not in version:
                preferred = api.get('preferred')
                versions = api.get('versions')
                if not isinstance(preferred, str) or not isinstance(versions, dict):
                    malformed = provider_matches or malformed
                    continue
                selected_version = versions.get(preferred)
                if not isinstance(selected_version, dict):
                    malformed = provider_matches or malformed
                    continue
                version = selected_version
            info = version.get('info')
            provider_name = info.get('x-providerName') if isinstance(info, dict) else None
            if not provider_matches and not self._matches_target(provider_name):
                continue
            if not isinstance(info, dict):
                malformed = True
            if spec_url := self._spec_url(version.get('swaggerUrl')):
                if spec_url not in seen_spec_urls:
                    seen_spec_urls.add(spec_url)
                    spec_urls.append(spec_url)
            else:
                malformed = True

        spec_failure: str | None = None
        for spec_url in spec_urls:
            spec_response = await self._fetch(spec_url)
            if spec_response is None:
                if self._report is None:
                    self._stop('failed', 'transport-error')
                elif self._report.stop_reason in {'invalid-response', 'response-limit'}:
                    spec_failure = spec_failure or self._report.stop_reason
                    continue
                return
            if spec_response.status == 429:
                self._stop('rate-limited', 'http-429')
                return
            if spec_response.status in {401, 403}:
                self._stop('failed', 'access-denied')
                return
            if spec_response.status in {404, 410}:
                spec_failure = spec_failure or f'http-{spec_response.status}'
                continue
            if 400 <= spec_response.status < 500:
                self._stop('failed', f'http-{spec_response.status}')
                return
            if not 200 <= spec_response.status < 300:
                self._stop('failed', f'http-{spec_response.status}')
                return
            if not isinstance(spec_response.body, dict):
                malformed = True
                continue
            malformed = self._parse_spec(spec_response.body) or malformed

        if malformed:
            self._stop('failed', 'invalid-response')
        elif spec_failure is not None:
            self._stop('failed', spec_failure)
        elif self.protective_limit_reached:
            self._stop('failed', 'result-cap')
        elif self.result_limit_reached:
            self._stop('completed', 'result-limit')
        elif directory_limit_reached:
            self._stop('failed', 'directory-entry-limit')

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_emails(self) -> set[str]:
        return self.totalemails

    async def get_urls(self) -> set[str]:
        return self.urls

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        self._report = None
        self.result_limit_reached = False
        self.protective_limit_reached = False
        try:
            async with asyncio.timeout(self.MAX_RUNTIME_SECONDS):
                await self.do_search()
        except TimeoutError:
            self._stop('failed', 'runtime-limit')
        return self._report
