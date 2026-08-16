import logging
from ipaddress import ip_address as normalize_ip_address
from typing import Any
from urllib.parse import urlparse

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname

logger = logging.getLogger(__name__)


class SearchSherlockeye:
    """Sherlockeye reverse search engine for OSINT investigations.

    Uses the synchronous search endpoint to collect domain-related intelligence
    such as subdomains, emails, and IP addresses from multiple providers.

    API docs: https://docs.sherlockeye.io/
    """

    SYNC_SEARCH_URL = 'https://api.sherlockeye.io/v1/searches/sync'
    DEFAULT_TIMEOUT_SECONDS = 60

    def __init__(self, word: str) -> None:
        self.word = word
        self.key = Core.sherlockeye_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('sherlockeye')
        self.totalhosts: set[str] = set()
        self.totalemails: set[str] = set()
        self.totalips: set[str] = set()
        self.results: list[dict[str, Any]] = []
        self.proxy: bool | str = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _has_results(self) -> bool:
        return bool(self.totalhosts or self.totalemails or self.totalips)

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self._has_results() else status
        self.stop_reason = reason

    def _headers(self) -> dict[str, str]:
        return {
            'User-Agent': Core.get_user_agent(),
            'Authorization': f'Bearer {self.key}',
            'Content-Type': 'application/json',
        }

    def _add_hostname(self, hostname: str) -> None:
        if normalized := normalize_scoped_hostname(hostname, self.word):
            self.totalhosts.add(normalized)

    def _add_email(self, email: str) -> None:
        normalized_email = email.strip().lower()
        local_part, separator, domain = normalized_email.rpartition('@')
        if local_part and separator and (normalized_domain := normalize_scoped_hostname(domain, self.word)):
            self.totalemails.add(f'{local_part}@{normalized_domain}')

    def _add_ip(self, ip_address: str) -> None:
        try:
            self.totalips.add(str(normalize_ip_address(ip_address.strip())))
        except ValueError:
            return

    def _extract_from_link(self, link: str) -> bool:
        try:
            parsed = urlparse(link.strip())
        except ValueError:
            return True
        if parsed.hostname:
            self._add_hostname(parsed.hostname)
        return False

    def _extract_result(self, result: dict[str, Any]) -> bool:
        attributes = result.get('attributes')
        if not isinstance(attributes, dict):
            return True

        malformed = False

        domain = attributes.get('domain')
        if isinstance(domain, str):
            self._add_hostname(domain)
        elif domain is not None:
            malformed = True

        email = attributes.get('email')
        if isinstance(email, str):
            self._add_email(email)
        elif email is not None:
            malformed = True

        ip_address = attributes.get('ip')
        if isinstance(ip_address, str):
            self._add_ip(ip_address)
        elif ip_address is not None:
            malformed = True

        link = attributes.get('link')
        if isinstance(link, str):
            malformed |= self._extract_from_link(link)
        elif link is not None:
            malformed = True
        return malformed

    def _extract_response(self, response: dict[str, Any]) -> None:
        if response.get('success') is False:
            logger.info('Sherlockeye API error')
            self._stop('failed', 'provider-error')
            return

        data = response.get('data')
        if not isinstance(data, dict):
            self._stop('failed', 'invalid-response')
            return

        search_results = data.get('results')
        if not isinstance(search_results, list):
            self._stop('failed', 'invalid-response')
            return

        self.results = search_results
        malformed = False
        for result in search_results:
            if isinstance(result, dict):
                malformed |= self._extract_result(result)
            else:
                malformed = True
        if malformed:
            self._stop('failed', 'invalid-response')
        elif self.execution_status is None:
            self.execution_status = 'completed'
            self.stop_reason = None if self._has_results() else 'no-results'

    async def do_search(self) -> None:
        payload = {
            'type': 'domain',
            'value': self.word,
            'timeoutSeconds': self.DEFAULT_TIMEOUT_SECONDS,
        }
        try:
            async with AsyncFetcher.open_session(
                headers=self._headers(),
                proxy=self.proxy,
                request_timeout=self.DEFAULT_TIMEOUT_SECONDS + 30,
            ) as session:
                response = await AsyncFetcher.post_fetch(
                    self.SYNC_SEARCH_URL,
                    session=session,
                    json=True,
                    include_metadata=True,
                    json_body=payload,
                )
                if error := provider_http_error(response):
                    self._stop(*error)
                    status = response.status if isinstance(response, FetcherResponse) else 'transport'
                    logger.info('Sherlockeye API request failed with status %s: %s', status, error[1])
                    return
                assert isinstance(response, FetcherResponse)
                if response.status != 200:
                    self._stop('failed', f'http-{response.status}')
                    logger.info('Sherlockeye API request failed with status %s', response.status)
                    return
                if isinstance(response.body, dict):
                    self._extract_response(response.body)
                else:
                    self._stop('failed', 'invalid-response')
        except Exception as error:
            self._stop('failed', 'transport-error')
            logger.info('Sherlockeye API error: %s', type(error).__name__)

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_emails(self) -> set[str]:
        return self.totalemails

    async def get_ips(self) -> set[str]:
        return self.totalips

    async def get_results(self) -> list[dict[str, Any]]:
        return self.results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        await self.do_search()
