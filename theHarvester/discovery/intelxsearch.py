import asyncio
import logging
from email.errors import HeaderParseError
from email.headerregistry import Address
from typing import Any
from urllib.parse import urlparse

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core
from theHarvester.parsers import intelxparser

logger = logging.getLogger(__name__)


def _normalize_scoped_hostname(value: object, target: str) -> str | None:
    if not isinstance(value, str):
        return None
    hostname = value.strip().lower().rstrip('.')
    normalized_target = target.strip().lower().rstrip('.')
    if hostname == normalized_target or hostname.endswith(f'.{normalized_target}'):
        return hostname
    return None


class SearchIntelx:
    """Search the Intelligence X Phonebook API.

    API documentation: https://github.com/IntelligenceX/SDK
    """

    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.intelx_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('Intelx')
        self.database = 'https://2.intelx.io'
        self.results: dict[str, Any] = {}
        self.emails: list[str] = []
        self.hostnames: list[str] = []
        self.interesting_urls: list[str] = []
        self.limit: int = 10000
        self.proxy = False
        self.offset = 0

    async def do_search(self) -> None:
        try:
            headers = {
                'x-key': self.key,
                'User-Agent': f'{Core.get_user_agent()}-theHarvester',
                'Content-Type': 'application/json',
            }
            data = {
                'term': self.word,
                'buckets': [],
                'lookuplevel': 0,
                'maxresults': self.limit,
                'timeout': 5,
                'datefrom': '',
                'dateto': '',
                'sort': 4,  # Sort by date descending for faster relevant results
                'media': 0,
                'terminate': [],
                'target': 0,
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(f'{self.database}/phonebook/search', headers=headers, json=data) as total_resp:
                    search_data = await total_resp.json()
                    if not search_data['success']:
                        logger.info('IntelX search request failed')
                        return
                    phonebook_id = search_data['id']

                await asyncio.sleep(2)  # Reduced sleep time as 5s is excessive

                async with session.get(
                    f'{self.database}/phonebook/search/result?id={phonebook_id}&limit={self.limit}&offset={self.offset}',
                    headers=headers,
                ) as resp:
                    self.results = await resp.json()

        except Exception as e:
            logger.info(f'An exception has occurred in Intelx: {e}')

    async def process(self, proxy: bool = False):
        self.proxy = proxy
        await self.do_search()
        intelx_parser = intelxparser.Parser()
        raw_emails, raw_selectors = await intelx_parser.parse_dictionaries(self.results)
        emails: set[str] = set()
        interesting_urls: set[str] = set()
        hostnames: set[str] = set()

        for email in raw_emails:
            if email.count('@') != 1:
                continue
            try:
                address = Address(addr_spec=email.strip().lower())
            except (HeaderParseError, ValueError):
                continue
            if address.username and (normalized_domain := _normalize_scoped_hostname(address.domain, self.word)):
                emails.add(f'{address.username}@{normalized_domain}')

        for selector in raw_selectors:
            try:
                parsed = urlparse(selector if '://' in selector else f'//{selector}')
            except ValueError:
                continue
            interesting_urls.add(selector)
            if normalized_hostname := _normalize_scoped_hostname(parsed.hostname, self.word):
                hostnames.add(normalized_hostname)

        self.emails = sorted(emails)
        self.interesting_urls = sorted(interesting_urls)
        self.hostnames = sorted(hostnames)

    async def get_emails(self) -> list[str]:
        return self.emails

    async def get_hostnames(self) -> list[str]:
        return self.hostnames

    async def get_interestingurls(self) -> list[str]:
        return self.interesting_urls
