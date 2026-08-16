import logging
from datetime import UTC, datetime
from ipaddress import ip_address
from urllib.parse import urlparse

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.asn_attribution import AsnAttributionObservation, SubjectKind
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.result_values import normalize_asn

logger = logging.getLogger(__name__)

# from theHarvester.parsers import myparser


class SearchOnyphe:
    """Collect ONYPHE results and retain physical/logical IP attribution.

    ONYPHE documents the root ``asn``/``organization`` pair as physical
    hosting data and ``geolocus.asn``/``geolocus.organization`` as logical
    WHOIS data. Both stay separate and are linked to the record's primary IP.
    """

    MAX_RESULTS = 10_000

    def __init__(self, word: str, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError('ONYPHE limit must be a positive integer')
        self.word = word
        self.limit = limit
        self.response: object = {}
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.asns: set = set()
        self.asn_attributions: set[AsnAttributionObservation] = set()
        self.key = Core.onyphe_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('onyphe')
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _has_results(self) -> bool:
        return bool(self.totalhosts or self.totalips or self.asns)

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self._has_results() else status
        self.stop_reason = reason

    async def do_search(self) -> None:
        base_url = 'https://www.onyphe.io/api/v2/search/'
        headers = {
            'User-Agent': Core.get_user_agent(),
            'Content-Type': 'application/json',
            'Authorization': f'bearer {self.key}',
        }
        page = 1
        records_seen = 0
        result_limit = min(self.limit, self.MAX_RESULTS)
        page_size = min(result_limit, self.MAX_RESULTS)
        last_total = 0
        try:
            async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy) as session:
                while records_seen < result_limit:
                    remaining = result_limit - records_seen
                    metadata = await AsyncFetcher.fetch(
                        session=session,
                        url=base_url,
                        params={'q': f'domain:{self.word}', 'page': page, 'size': page_size},
                        json=True,
                        include_metadata=True,
                    )
                    if error := provider_http_error(metadata):
                        self._stop(*error)
                        return
                    assert isinstance(metadata, FetcherResponse)
                    if not isinstance(metadata.body, dict):
                        self._stop('failed', 'invalid-response')
                        return
                    response_text = metadata.body.get('text')
                    if response_text != 'Success':
                        self._stop('failed', 'provider-error' if isinstance(response_text, str) else 'invalid-response')
                        return
                    results = metadata.body.get('results')
                    max_page = metadata.body.get('max_page', 1)
                    total = metadata.body.get('total', len(results) if isinstance(results, list) else None)
                    if (
                        not isinstance(results, list)
                        or isinstance(max_page, bool)
                        or not isinstance(max_page, int)
                        or max_page < 1
                        or isinstance(total, bool)
                        or not isinstance(total, int)
                        or total < 0
                    ):
                        self._stop('failed', 'invalid-response')
                        return

                    page_results = results[:remaining]
                    records_seen += len(page_results)
                    last_total = total
                    self.response = {**metadata.body, 'results': page_results}
                    if await self.parse_onyphe_resp_json():
                        self._stop('failed', 'invalid-response')
                    expected_records = min(total, result_limit)
                    if (not results or page >= max_page) and records_seen < expected_records:
                        self._stop('failed', 'invalid-response')
                        break
                    if not results or page >= max_page or records_seen >= expected_records:
                        break
                    page += 1
        except Exception as error:
            self._stop('failed', 'transport-error')
            logger.info('Onyphe request failed: %s', type(error).__name__)
            return

        if self.limit > self.MAX_RESULTS and last_total > self.MAX_RESULTS and records_seen >= self.MAX_RESULTS:
            self._stop('failed', 'provider-limit')
        if self.execution_status is not None and self._has_results():
            self.execution_status = 'partial'
        elif self.execution_status is None:
            self.execution_status = 'completed'
            self.stop_reason = None if self._has_results() else 'no-results'

    async def parse_onyphe_resp_json(self) -> bool:
        if not isinstance(self.response, dict):
            return True
        results = self.response.get('results')
        if not isinstance(results, list):
            return True

        malformed = False
        for result in results:
            if not isinstance(result, dict):
                malformed = True
                continue

            primary_ip = None
            alternative_ips = result.get('alternativeip', [])
            if not isinstance(alternative_ips, list):
                malformed = True
                alternative_ips = []
            ip_candidates = [result['ip']] if 'ip' in result else []
            ip_candidates.extend(alternative_ips)
            for index, candidate in enumerate(ip_candidates):
                if not isinstance(candidate, str):
                    malformed = True
                    continue
                try:
                    normalized_ip = str(ip_address(candidate.strip()))
                    self.totalips.add(normalized_ip)
                    if index == 0 and 'ip' in result:
                        primary_ip = normalized_ip
                except ValueError:
                    malformed = True

            host_candidates = []
            urls = result.get('url', [])
            if not isinstance(urls, list):
                malformed = True
            else:
                for url in urls:
                    if not isinstance(url, str):
                        malformed = True
                        continue
                    try:
                        hostname = urlparse(url).hostname
                    except ValueError:
                        malformed = True
                        continue
                    if hostname:
                        host_candidates.append(hostname)

            for key in ('domain', 'hostname', 'subdomains', 'reverse'):
                values = result.get(key, [])
                if not isinstance(values, list):
                    malformed = True
                    continue
                host_candidates.extend(values)

            subject = result.get('subject')
            if subject is not None:
                if isinstance(subject, dict) and isinstance(subject.get('altname', []), list):
                    host_candidates.extend(subject.get('altname', []))
                else:
                    malformed = True

            geolocus = result.get('geolocus')
            geolocus_asn = None
            geolocus_organization = None
            if geolocus is not None:
                if isinstance(geolocus, dict) and isinstance(geolocus.get('domain', []), list):
                    host_candidates.extend(geolocus.get('domain', []))
                    geolocus_asn = geolocus.get('asn')
                    geolocus_organization = geolocus.get('organization')
                else:
                    malformed = True

            for candidate in host_candidates:
                if not isinstance(candidate, str):
                    malformed = True
                    continue
                if hostname := normalize_scoped_hostname(candidate, self.word):
                    self.totalhosts.add(hostname)

            attribution_pairs = (
                (result.get('asn'), result.get('organization')),
                (geolocus_asn, geolocus_organization),
            )
            for asn, organization in attribution_pairs:
                if asn is None:
                    continue
                if isinstance(asn, (str, int)):
                    try:
                        normalized_asn = normalize_asn(asn)
                    except ValueError:
                        malformed = True
                        continue
                    self.asns.add(normalized_asn)
                else:
                    malformed = True
                    continue
                if organization is None:
                    continue
                if not isinstance(organization, str) or not organization.strip():
                    malformed = True
                    continue
                collected_at = datetime.now(UTC)
                subjects: list[tuple[SubjectKind, str]] = [('ip', primary_ip)] if primary_ip is not None else []
                for subject_kind, subject_value in subjects:
                    try:
                        self.asn_attributions.add(
                            AsnAttributionObservation(
                                'source',
                                'onyphe',
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

    async def get_asns(self) -> set:
        return self.asns

    async def get_asn_attributions(self) -> set[AsnAttributionObservation]:
        return self.asn_attributions

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        await self.do_search()
