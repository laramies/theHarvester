import logging
from datetime import UTC, datetime
from ipaddress import ip_address
from urllib.parse import urlparse

from theHarvester.discovery.constants import MissingKey
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

    def __init__(self, word) -> None:
        self.word = word
        self.response = ''
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.asns: set = set()
        self.asn_attributions: set[AsnAttributionObservation] = set()
        self.key = Core.onyphe_key()
        if self.key is None:
            raise MissingKey('onyphe')
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    async def do_search(self) -> None:
        # https://www.onyphe.io/docs/apis/search
        # https://www.onyphe.io/search?q=domain%3Acharter.com&captcharesponse=j5cGT
        # base_url = f'https://www.onyphe.io/api/v2/search/?q=domain:domain:{self.word}'
        base_url = f'https://www.onyphe.io/api/v2/search/?q=domain:{self.word}'
        headers = {
            'User-Agent': Core.get_user_agent(),
            'Content-Type': 'application/json',
            'Authorization': f'bearer {self.key}',
        }
        try:
            response = await AsyncFetcher.fetch_all(
                [base_url],
                json=True,
                headers=headers,
                proxy=self.proxy,
                include_metadata=True,
            )
        except Exception as error:
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            logger.info('Onyphe request failed: %s', type(error).__name__)
            return

        metadata = response[0] if response and isinstance(response[0], FetcherResponse) else None
        if metadata is None:
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            return
        if metadata.status == 429:
            self.execution_status = 'rate-limited'
            self.stop_reason = 'http-429'
            return
        if metadata.status in {401, 403}:
            self.execution_status = 'failed'
            self.stop_reason = 'access-denied'
            return
        if not 200 <= metadata.status < 300:
            self.execution_status = 'failed'
            self.stop_reason = f'http-{metadata.status}'
            return

        self.response = metadata.body
        await self.parse_onyphe_resp_json()

    async def parse_onyphe_resp_json(self):
        if not isinstance(self.response, dict):
            self.execution_status = 'failed'
            self.stop_reason = 'invalid-response'
            return
        response_text = self.response.get('text')
        if response_text != 'Success':
            self.execution_status = 'failed'
            self.stop_reason = 'provider-error' if isinstance(response_text, str) else 'invalid-response'
            logger.info('Onyphe API query did not succeed')
            return
        results = self.response.get('results')
        if not isinstance(results, list):
            self.execution_status = 'failed'
            self.stop_reason = 'invalid-response'
            return

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

        if malformed:
            self.execution_status = 'partial' if self.totalhosts or self.totalips or self.asns else 'failed'
            self.stop_reason = 'invalid-response'
        else:
            self.execution_status = 'completed'
            self.stop_reason = None if self.totalhosts or self.totalips or self.asns else 'no-results'

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
        await self.do_search()
