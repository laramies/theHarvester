import logging
from datetime import UTC, datetime
from ipaddress import ip_address
from urllib.parse import urlsplit

from theHarvester.lib.asn_attribution import AsnAttributionObservation, SubjectKind
from theHarvester.lib.core import AsyncFetcher, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.result_values import normalize_asn

logger = logging.getLogger(__name__)


class SearchUrlscan:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.urls: set = set()
        self.totalasns: set = set()
        self.asn_attributions: set[AsnAttributionObservation] = set()
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _has_results(self) -> bool:
        return bool(self.totalhosts or self.totalips or self.urls or self.totalasns)

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self._has_results() else status
        self.stop_reason = reason

    @staticmethod
    def _cursor(result: object) -> str | None:
        if not isinstance(result, dict):
            return None
        sort = result.get('sort')
        if not isinstance(sort, list) or not sort:
            return None
        values = []
        for value in sort:
            if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                return None
            serialized = str(value).strip()
            if not serialized:
                return None
            values.append(serialized)
        return ','.join(values)

    def _parse_results(self, results: list, collected_at: datetime) -> bool:
        malformed = False
        for result in results:
            if not isinstance(result, dict):
                malformed = True
                continue
            if 'page' not in result:
                continue
            page = result['page']
            if not isinstance(page, dict):
                malformed = True
                continue
            scoped = False
            scoped_hosts: set[str] = set()
            if 'domain' in page:
                domain = page['domain']
                if not isinstance(domain, str) or not domain:
                    malformed = True
                elif normalized_domain := normalize_scoped_hostname(domain, self.word):
                    self.totalhosts.add(normalized_domain)
                    scoped_hosts.add(normalized_domain)
                    scoped = True
            if 'url' in page:
                value = page['url']
                if not isinstance(value, str) or not value:
                    malformed = True
                else:
                    try:
                        hostname = urlsplit(value).hostname
                    except ValueError:
                        malformed = True
                    else:
                        if hostname is None:
                            malformed = True
                        elif normalize_scoped_hostname(hostname, self.word):
                            self.urls.add(value)
                            scoped = True
            if not scoped:
                continue
            scoped_ips: set[str] = set()
            if 'ip' in page:
                address = page['ip']
                if not isinstance(address, str):
                    malformed = True
                else:
                    try:
                        normalized_ip = str(ip_address(address.strip()))
                        self.totalips.add(normalized_ip)
                        scoped_ips.add(normalized_ip)
                    except ValueError:
                        malformed = True
            normalized_asn = None
            if 'asn' in page:
                asn = page['asn']
                if not isinstance(asn, str):
                    malformed = True
                else:
                    try:
                        normalized_asn = normalize_asn(asn)
                    except ValueError:
                        malformed = True
                    else:
                        self.totalasns.add(normalized_asn)
            organization = page.get('asnname')
            if organization is not None and not isinstance(organization, str):
                malformed = True
                organization = None
            if normalized_asn is not None and isinstance(organization, str) and organization.strip():
                subjects: list[tuple[SubjectKind, str]] = [
                    *(('hostname', hostname) for hostname in scoped_hosts),
                    *(('ip', address) for address in scoped_ips),
                ]
                for subject_kind, subject_value in subjects:
                    try:
                        self.asn_attributions.add(
                            AsnAttributionObservation(
                                'source',
                                'urlscan',
                                normalized_asn,
                                organization,
                                subject_kind,
                                subject_value,
                                collected_at,
                            )
                        )
                    except ValueError:
                        malformed = True
        return malformed

    async def do_search(self) -> None:
        url = 'https://urlscan.io/api/v1/search/'
        collected_at = datetime.now(UTC)
        cursor = None
        seen_cursors: set[str] = set()
        malformed = False
        try:
            async with AsyncFetcher.open_session(proxy=self.proxy) as session:
                while True:
                    params = {'q': f'domain:{self.word}'}
                    if cursor is not None:
                        params['search_after'] = cursor
                    response = await AsyncFetcher.fetch(
                        session=session,
                        url=url,
                        params=params,
                        json=True,
                        include_metadata=True,
                    )

                    if not isinstance(response, FetcherResponse):
                        self._stop('failed', 'transport-error')
                        return
                    if response.status == 429:
                        self._stop('rate-limited', 'http-429')
                        return
                    if response.status in {401, 403}:
                        self._stop('failed', 'access-denied')
                        return
                    if not 200 <= response.status < 300:
                        self._stop('failed', f'http-{response.status}')
                        return
                    if not isinstance(response.body, dict) or not isinstance(response.body.get('results'), list):
                        self._stop('failed', 'invalid-response')
                        return

                    results = response.body['results']
                    if not results:
                        if malformed:
                            self._stop('failed', 'invalid-response')
                        else:
                            self.execution_status = 'completed'
                            self.stop_reason = None if self._has_results() else 'no-results'
                        return

                    malformed = self._parse_results(results, collected_at) or malformed
                    next_cursor = self._cursor(results[-1])
                    if next_cursor is None:
                        self._stop('failed', 'invalid-cursor')
                        return
                    if next_cursor in seen_cursors:
                        self._stop('failed', 'repeated-cursor')
                        return
                    seen_cursors.add(next_cursor)
                    cursor = next_cursor
        except Exception as error:
            self._stop('failed', 'transport-error')
            logger.info('URLScan request failed: %s', type(error).__name__)

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def get_urls(self) -> set:
        return self.urls

    async def get_asns(self) -> set:
        return self.totalasns

    async def get_asn_attributions(self) -> set[AsnAttributionObservation]:
        return self.asn_attributions

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
