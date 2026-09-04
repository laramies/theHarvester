import logging
from typing import Any
from urllib.parse import urlparse

from theHarvester.lib.core import AsyncFetcher


class SearchLunar:
    """Lunar Domain Exposure API integration.

    Lunar's Domain Exposure endpoint returns domain-level exposure intelligence
    aggregated from infostealer logs and data breaches: exposure counts, a
    monthly activity timeline, observed malware families, affected services and
    the login URLs seen in stealer/breach records.

    The endpoint is free and does not require an API key. It is an *enrichment*
    source for an already-known target domain rather than a subdomain
    enumeration source, but the ``top_login_urls`` it returns frequently expose
    real subdomains of the target (auth portals, VPN gateways, ADFS endpoints),
    which are surfaced as hostnames and interesting URLs.

    API example:
        https://api.lunarcyber.com/domain-exposure?domain=example.com
    """

    BASE_URL = 'https://api.lunarcyber.com/domain-exposure'
    READY_STATUS = 'REPORT_READY'

    def __init__(self, word: str) -> None:
        self.word = word.strip().lower()
        self.totalhosts: set[str] = set()
        self.interesting_urls: set[str] = set()
        self.exposure: dict[str, Any] = {}
        self.malware_families: list[dict[str, Any]] = []
        self.proxy: bool = False
        self.logger = logging.getLogger(__name__)

    async def do_search(self) -> None:
        """Fetch and parse the domain exposure report."""
        url = f'{self.BASE_URL}?domain={self.word}'
        try:
            responses = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        except Exception as error:
            self.logger.error(f'Lunar API request failed for {self.word}: {error}')
            return

        if not responses or not isinstance(responses[0], dict):
            self.logger.warning(f'Lunar returned an unexpected response for {self.word}')
            return

        payload = responses[0]
        status = payload.get('status')
        if status and status != self.READY_STATUS:
            # The report can be generated asynchronously for domains Lunar has
            # not seen recently; in that case there is nothing to parse yet.
            self.logger.info(f'Lunar report for {self.word} is not ready (status: {status})')
            return

        report = payload.get('report')
        if not isinstance(report, dict):
            self.logger.info(f'Lunar returned no exposure report for {self.word}')
            return

        self._parse_report(report)

    def _parse_report(self, report: dict[str, Any]) -> None:
        """Extract hostnames, interesting URLs and an exposure summary."""
        top_login_urls = report.get('top_login_urls')
        if isinstance(top_login_urls, list):
            self._extract_login_urls(top_login_urls)

        malware_breakdown = report.get('malware_family_breakdown')
        if isinstance(malware_breakdown, list):
            self.malware_families = [entry for entry in malware_breakdown if isinstance(entry, dict)]

        self.exposure = self._build_summary(report)
        self._log_summary()

    def _extract_login_urls(self, top_login_urls: list[dict[str, Any]]) -> None:
        """Pull hostnames and URLs out of Lunar's ``top_login_urls`` records.

        Entries may be bare hostnames (``sts.example.com``), full URLs
        (``https://sts.example.com``) or wildcard paths
        (``sts.example.com/adfs/**/``). Only hostnames belonging to the target
        domain are kept as hosts; every parseable login URL is retained as an
        interesting URL.
        """
        for entry in top_login_urls:
            if not isinstance(entry, dict):
                continue
            raw_url = entry.get('url')
            if not isinstance(raw_url, str):
                continue
            raw_url = raw_url.strip()
            if not raw_url:
                continue

            candidate = raw_url if '://' in raw_url else f'http://{raw_url}'
            hostname = urlparse(candidate).hostname
            if not hostname or '*' in hostname:
                continue
            hostname = hostname.lower()

            self.interesting_urls.add(raw_url)
            if hostname == self.word or hostname.endswith(f'.{self.word}'):
                self.totalhosts.add(hostname)

    @staticmethod
    def _build_summary(report: dict[str, Any]) -> dict[str, Any]:
        """Condense the verbose report into a flat exposure summary."""
        summary = report['summary'] if isinstance(report.get('summary'), dict) else {}
        breach = report['data_breach_summary'] if isinstance(report.get('data_breach_summary'), dict) else {}
        infostealer = report['infostealer_summary'] if isinstance(report.get('infostealer_summary'), dict) else {}

        return {
            'domain': report.get('domain'),
            'generated_at': report.get('generated_at'),
            'total_events': summary.get('total_events'),
            'infostealer_events': summary.get('infostealer_events'),
            'data_breach_events': summary.get('data_breach_events'),
            'employee_events': summary.get('employee_events'),
            'client_events': summary.get('client_events'),
            'first_seen': summary.get('first_seen'),
            'last_seen': summary.get('last_seen'),
            'malware_families_observed': infostealer.get('malware_families_observed'),
            'known_breach_sources_count': breach.get('known_breach_sources_count'),
        }

    def _log_summary(self) -> None:
        """Log the headline exposure numbers so operators see the intelligence."""
        total = self.exposure.get('total_events')
        if not total:
            self.logger.info(f'Lunar found no exposure events for {self.word}')
            return

        top_families = ', '.join(
            f'{entry.get("family")} ({entry.get("events")})' for entry in self.malware_families[:3] if entry.get('family')
        )
        self.logger.info(
            f'Lunar exposure for {self.word}: {total} events '
            f'({self.exposure.get("infostealer_events")} infostealer, '
            f'{self.exposure.get("data_breach_events")} data breach), '
            f'window {self.exposure.get("first_seen")} to {self.exposure.get("last_seen")}'
            + (f'; top malware: {top_families}' if top_families else '')
        )

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_interestingurls(self) -> list[str]:
        return sorted(self.interesting_urls)

    async def get_exposure(self) -> dict[str, Any]:
        """Return the flattened exposure summary for this domain."""
        return self.exposure

    async def get_malware_families(self) -> list[dict[str, Any]]:
        """Return the observed infostealer malware family breakdown."""
        return self.malware_families

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
