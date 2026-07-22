import logging
import random
from typing import Any
from urllib.parse import urlparse

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core

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
        if self.key is None:
            raise MissingKey('sherlockeye')
        self.totalhosts: set[str] = set()
        self.totalemails: set[str] = set()
        self.totalips: set[str] = set()
        self.results: list[dict[str, Any]] = []
        self.proxy: bool | str = False

    def _headers(self) -> dict[str, str]:
        return {
            'User-Agent': Core.get_user_agent(),
            'Authorization': f'Bearer {self.key}',
            'Content-Type': 'application/json',
        }

    def _proxy_url(self) -> str | None:
        if isinstance(self.proxy, str) and self.proxy:
            return self.proxy
        if isinstance(self.proxy, bool) and self.proxy:
            try:
                proxy_list = Core.proxy_list()
                proxy_urls = [*proxy_list.get('http', []), *proxy_list.get('socks5', [])]
                if proxy_urls:
                    return random.choice(proxy_urls)
            except Exception:
                return None
        return None

    def _add_hostname(self, hostname: str) -> None:
        hostname = hostname.strip().lower().removeprefix('www.')
        if hostname.endswith(f'.{self.word}') or hostname == self.word:
            self.totalhosts.add(hostname)

    def _add_email(self, email: str) -> None:
        email = email.strip().lower()
        if '@' in email and self.word in email:
            self.totalemails.add(email)

    def _add_ip(self, ip_address: str) -> None:
        ip_address = ip_address.strip()
        if ip_address:
            self.totalips.add(ip_address)

    def _extract_from_link(self, link: str) -> None:
        parsed = urlparse(link.strip())
        if parsed.hostname:
            self._add_hostname(parsed.hostname)

    def _extract_result(self, result: dict[str, Any]) -> None:
        attributes = result.get('attributes')
        if not isinstance(attributes, dict):
            return

        domain = attributes.get('domain')
        if isinstance(domain, str):
            self._add_hostname(domain)

        email = attributes.get('email')
        if isinstance(email, str):
            self._add_email(email)

        ip_address = attributes.get('ip')
        if isinstance(ip_address, str):
            self._add_ip(ip_address)

        link = attributes.get('link')
        if isinstance(link, str):
            self._extract_from_link(link)

    def _extract_response(self, response: dict[str, Any]) -> None:
        if response.get('success') is False:
            logger.info('Sherlockeye API error')
            return

        data = response.get('data')
        if not isinstance(data, dict):
            return

        search_results = data.get('results')
        if not isinstance(search_results, list):
            return

        self.results = search_results
        for result in search_results:
            if isinstance(result, dict):
                self._extract_result(result)

    async def do_search(self) -> None:
        payload = {
            'type': 'domain',
            'value': self.word,
            'timeoutSeconds': self.DEFAULT_TIMEOUT_SECONDS,
        }
        timeout = aiohttp.ClientTimeout(total=self.DEFAULT_TIMEOUT_SECONDS + 30)

        try:
            async with aiohttp.ClientSession(headers=self._headers(), timeout=timeout) as session:
                async with session.post(
                    self.SYNC_SEARCH_URL,
                    json=payload,
                    proxy=self._proxy_url(),
                ) as response:
                    if response.status != 200:
                        logger.info(f'Sherlockeye API request failed with status {response.status}')
                        return

                    response_data = await response.json()
                    if isinstance(response_data, dict):
                        self._extract_response(response_data)
        except Exception as error:
            logger.info(f'Sherlockeye API error: {error}')

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
        await self.do_search()
