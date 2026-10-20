import asyncio
import logging
import re
import ssl
import unicodedata
from typing import Any
from urllib.parse import quote

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, ResponseStreamError
from theHarvester.lib.hostnames import normalize_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchHaveIBeenRansom:
    """List the ransomware leak-site posts and data breaches indexed for a domain.

    Provider API:
    https://haveibeenransom.com/howapi

    The metadata endpoint returns one entry per leak (victim or dump title, group or
    channel, discovery date) and never the leaked records themselves. Each page holds
    20 entries and is one request against the account's daily quota.
    """

    BASE_URL = 'https://haveibeenransom.com/api/metadata/domain'

    # The provider aggregates at most 10,000 leaks per search, which is 500 pages of 20.
    # The guard bounds the conversation if a response keeps reporting further pages.
    MAX_PAGES = 500

    def __init__(self, word: str, limit: int | None = None) -> None:
        self.word = word
        self.limit = limit
        key = Core.haveibeenransom_key()
        self.api_key = key.strip() if isinstance(key, str) else ''
        if not self.api_key:
            raise MissingKey('HaveIBeenRansom')
        self.breach_names: set[str] = set()
        self.proxy: bool | str = False

    @staticmethod
    def _clean(value: object) -> str:
        if not isinstance(value, str):
            return ''
        return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', value)).strip()

    def _breach_name(self, entry: dict[str, Any]) -> str:
        # Ransomware posts carry the victim in post_title and the gang in group_name.
        # Breach dumps carry the dump title and the channel or collection it came from.
        title = self._clean(entry.get('post_title')) or self._clean(entry.get('website'))
        group = self._clean(entry.get('group_name'))
        if title and group:
            return f'{title} ({group})'
        return title

    async def do_search(self, domain: str) -> SourceExecutionReport | None:
        headers = {'Accept': 'application/json', 'Authorization': f'Bearer {self.api_key}'}
        path = f'{self.BASE_URL}/{quote(domain, safe="")}'
        seen_leaks: set[str] = set()
        malformed = False
        try:
            async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy, request_timeout=60) as session:
                for page in range(1, self.MAX_PAGES + 1):
                    url = path if page == 1 else f'{path}/{page}'
                    response = await AsyncFetcher.fetch_json(url, session=session)
                    if failure := provider_http_error(response):
                        logger.info('HaveIBeenRansom request failed: %s', failure[1])
                        return SourceExecutionReport(*failure)
                    body = response.body
                    if not isinstance(body, dict):
                        return SourceExecutionReport('failed', 'invalid-response')
                    # The documentation example nests entries under results and pagination;
                    # the API sends sources and the pagination fields at the top level.
                    entries = body['sources'] if 'sources' in body else body.get('results')
                    pagination = body.get('pagination')
                    has_next = (pagination if isinstance(pagination, dict) else body).get('has_next')
                    if not isinstance(entries, list) or not isinstance(has_next, bool):
                        return SourceExecutionReport('failed', 'invalid-response')

                    for entry in entries:
                        if not isinstance(entry, dict):
                            malformed = True
                            continue
                        # Newly indexed leaks can be repeated at the top of a later page.
                        leak_id = entry.get('id_source')
                        if isinstance(leak_id, (str, int)) and not isinstance(leak_id, bool):
                            if str(leak_id) in seen_leaks:
                                continue
                            seen_leaks.add(str(leak_id))
                        if not (name := self._breach_name(entry)):
                            malformed = True
                            continue
                        if self.limit is not None and len(self.breach_names) >= self.limit and name not in self.breach_names:
                            return self._stop(malformed, SourceExecutionReport('completed', 'result-limit'))
                        self.breach_names.add(name)

                    # Pages can come back short or empty while has_next is still true, because
                    # leaks without metadata are dropped from the page, so has_next decides.
                    if not has_next:
                        break
                    if self.limit is not None and len(self.breach_names) >= self.limit:
                        return self._stop(malformed, SourceExecutionReport('completed', 'result-limit'))
                else:
                    return self._stop(malformed, SourceExecutionReport('partial', 'provider-limit'))
        except ResponseStreamError as error:
            return SourceExecutionReport('failed', error.reason)
        return self._stop(malformed)

    @staticmethod
    def _stop(malformed: bool, report: SourceExecutionReport | None = None) -> SourceExecutionReport | None:
        # Entries that could not be read take precedence, so the run is not reported as complete.
        return SourceExecutionReport('failed', 'invalid-response') if malformed else report

    async def get_breach_names(self) -> set[str]:
        return self.breach_names

    async def process(self, proxy: bool | str = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        # The provider matches the domain field exactly, but treats * and ? as wildcards.
        try:
            domain = normalize_hostname(self.word)
        except ValueError:
            return SourceExecutionReport('failed', 'invalid-target')
        if '.' not in domain:
            return SourceExecutionReport('failed', 'invalid-target')
        try:
            return await self.do_search(domain)
        except asyncio.CancelledError:
            raise
        except aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError:
            return SourceExecutionReport('failed', 'transport-error')
