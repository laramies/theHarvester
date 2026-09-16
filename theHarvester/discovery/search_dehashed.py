import asyncio
import logging
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any

from aiohttp import ClientError

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from aiohttp import ClientSession

logger = logging.getLogger(__name__)


class SearchDehashed:
    def __init__(self, word: str, limit: int | None = 500) -> None:
        self.word = word
        self.key = (Core.dehashed_key() or '').strip()
        if not self.key:
            raise MissingKey('Dehashed')
        self.api = 'https://api.dehashed.com/v2/search'
        self.headers = {
            'Dehashed-Api-Key': self.key,
            'User-Agent': Core.get_user_agent(),
        }
        self.limit = max(limit, 0) if limit is not None else None
        self.emails: set[str] = set()
        self.ips: set[str] = set()
        self.proxy: bool = False

    async def _fetch_page(self, payload: dict[str, Any], session: ClientSession) -> Any:
        response = await AsyncFetcher.post_fetch(
            self.api,
            session=session,
            json_body=payload,
            json=True,
            include_metadata=True,
        )
        if isinstance(response, FetcherResponse) and response.status == 429:
            retry_after = response.headers.get('retry-after') or response.headers.get('Retry-After')
            try:
                delay = float(retry_after) if retry_after is not None else -1
            except ValueError:
                delay = -1
            if 0 <= delay <= 60:
                logger.info(f'\t[!] Dehashed rate limited; retrying once in {delay:g} seconds')
                await asyncio.sleep(delay)
                response = await AsyncFetcher.post_fetch(
                    self.api,
                    session=session,
                    json_body=payload,
                    json=True,
                    include_metadata=True,
                )
        return response

    def _retain_evidence(self, entries: list[object]) -> None:
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            email = entry.get('email')
            if isinstance(email, str):
                normalized_email = email.strip().lower()
                local, separator, domain = normalized_email.partition('@')
                if local and separator and domain and '@' not in domain:
                    self.emails.add(normalized_email)
            address = entry.get('ip_address')
            if isinstance(address, str):
                try:
                    self.ips.add(str(ip_address(address.strip())))
                except ValueError:
                    continue

    async def do_search(self, session: ClientSession | None = None) -> SourceExecutionReport | None:
        if session is None:
            try:
                async with AsyncFetcher.open_session(
                    headers=self.headers, proxy=self.proxy, request_timeout=720
                ) as owned_session:
                    return await self.do_search(owned_session)
            except ResponseStreamError as error:
                return SourceExecutionReport('failed', error.reason)
            except ClientError, OSError:
                logger.info('\t[!] Dehashed session failed')
                return SourceExecutionReport('failed', 'transport-error')

        logger.info(f'\t[+] Performing Dehashed search for: {self.word}')
        page = 1
        remaining = self.limit
        while remaining is None or remaining > 0:
            size = min(100, remaining) if remaining is not None else 100
            payload = {'query': self.word, 'page': page, 'size': size, 'wildcard': False, 'regex': False, 'de_dupe': False}
            try:
                response = await self._fetch_page(payload, session)
                if not isinstance(response, FetcherResponse):
                    logger.info('\t[!] Dehashed request failed')
                    return SourceExecutionReport('failed', 'transport-error')
                if failure := provider_http_error(response):
                    logger.info(f'\t[!] Dehashed request failed with HTTP {response.status}')
                    return SourceExecutionReport(*failure)
                data = response.body
                if not isinstance(data, dict) or not isinstance(entries := data.get('entries'), list):
                    logger.info('\t[!] Dehashed returned a malformed response')
                    return SourceExecutionReport('failed', 'invalid-response')
                if not entries:
                    break
                retained_entries = entries[:remaining] if remaining is not None else entries
                self._retain_evidence(retained_entries)
                if any(not isinstance(entry, dict) for entry in retained_entries):
                    return SourceExecutionReport('failed', 'invalid-response')
                if remaining is not None:
                    remaining -= len(retained_entries)
                logger.info(f'\t[+] Page {page} - Retrieved {len(retained_entries)} entries.')
                if len(entries) < size:
                    break
                page += 1
            except OSError, RuntimeError, ValueError:
                logger.info('\t[!] Dehashed request failed')
                return SourceExecutionReport('failed', 'transport-error')

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()

    async def get_emails(self) -> set[str]:
        return self.emails

    async def get_hostnames(self) -> set[str]:
        return set()

    async def get_ips(self) -> set[str]:
        return self.ips
