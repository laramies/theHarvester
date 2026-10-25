import asyncio
import logging
import re
import ssl
import unicodedata
from typing import Any, ClassVar
from urllib.parse import quote, urlencode

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, ResponseStreamError
from theHarvester.lib.hostnames import normalize_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchDarkEye:
    """List the ransomware leaks, data breaches, access leads and stealer logs DarkEye indexes for a domain.

    DarkEye publishes two APIs, each with its own key, and the source queries every one
    that has a key configured:

    - Have I Been Ransomed? (https://haveibeenransom.com/howapi): the metadata endpoint
      matches the exact domain and returns pages of 20 leaks, each page one request
      against the key's daily quota.
    - Breach House (https://breach.house/docs): the cross-source search returns
      ransomware, breach, lead and stealer records in one request, at most 200 per source.

    Each breach name is the victim or dump title, the group or channel, and the DarkEye
    product and category of the record. Leaked records themselves are never retrieved.
    """

    HIBR_PRODUCT = 'Have I Been Ransomed?'
    HIBR_URL = 'https://haveibeenransom.com/api/metadata/domain'
    BREACH_HOUSE_PRODUCT = 'Breach House'
    BREACH_HOUSE_URL = 'https://breach.house/api/v1/search'

    # Have I Been Ransomed? aggregates at most 10,000 leaks per search, which is 500 pages of 20.
    # The guard bounds the conversation if a response keeps reporting further pages.
    MAX_PAGES = 500
    # Breach House returns at most this many records per source in one search.
    BREACH_HOUSE_MAX_LIMIT = 200

    HIBR_CATEGORIES: ClassVar[dict[str, str]] = {'ransomware_leak': 'ransomware leak', 'traditional_breach': 'data breach'}
    BREACH_HOUSE_CATEGORIES: ClassVar[dict[str, str]] = {
        'ransomware': 'ransomware leak',
        'breaches': 'data breach',
        'leads': 'access lead',
        'stealers': 'stealer log',
    }

    def __init__(self, word: str, limit: int | None = None) -> None:
        self.word = word
        self.limit = limit
        hibr_key, breach_house_key = Core.darkeye_keys()
        self.hibr_key = hibr_key.strip() if isinstance(hibr_key, str) else ''
        self.breach_house_key = breach_house_key.strip() if isinstance(breach_house_key, str) else ''
        if not (self.hibr_key or self.breach_house_key):
            raise MissingKey('DarkEye')
        self.breach_names: set[str] = set()
        # Both products can list the same victim or breach, which is reported once.
        self.seen_records: set[tuple[str, str, str, str]] = set()
        self.proxy: bool | str = False

    @staticmethod
    def _clean(value: object) -> str:
        if not isinstance(value, str):
            return ''
        return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', value)).strip()

    def _limit_reached(self) -> bool:
        return self.limit is not None and len(self.breach_names) >= self.limit

    def _add(self, product: str, category: str, entry: dict[str, Any]) -> bool | None:
        """Record one entry. Returns False when it cannot be read and None at the result limit."""
        # Ransomware posts carry the victim in post_title and the gang in group_name.
        # Breach dumps carry the dump title and the channel or collection it came from.
        title = self._clean(entry.get('post_title')) or self._clean(entry.get('website'))
        if not title:
            return False
        group = self._clean(entry.get('group_name'))
        record = (category, title.casefold(), group.casefold(), self._clean(entry.get('discovered'))[:10])
        if record in self.seen_records:
            return True
        name = f'{title} ({group})' if group else title
        name = f'{name} [DarkEye | {product} | {category}]'
        if self._limit_reached() and name not in self.breach_names:
            return None
        self.seen_records.add(record)
        self.breach_names.add(name)
        return True

    async def search_hibr(self, domain: str) -> SourceExecutionReport | None:
        headers = {'Accept': 'application/json', 'Authorization': f'Bearer {self.hibr_key}'}
        path = f'{self.HIBR_URL}/{quote(domain, safe="")}'
        seen_leaks: set[str] = set()
        malformed = False
        async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy, request_timeout=60) as session:
            for page in range(1, self.MAX_PAGES + 1):
                url = path if page == 1 else f'{path}/{page}'
                response = await AsyncFetcher.fetch_json(url, session=session)
                if failure := provider_http_error(response):
                    logger.info('DarkEye %s request failed: %s', self.HIBR_PRODUCT, failure[1])
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
                    category = self.HIBR_CATEGORIES.get(self._clean(entry.get('leak_type')), 'data leak')
                    added = self._add(self.HIBR_PRODUCT, category, entry)
                    if added is None:
                        return self._stop(malformed, SourceExecutionReport('completed', 'result-limit'))
                    malformed = malformed or not added

                # Pages can come back short or empty while has_next is still true, because
                # leaks without metadata are dropped from the page, so has_next decides.
                if not has_next:
                    break
                if self._limit_reached():
                    return self._stop(malformed, SourceExecutionReport('completed', 'result-limit'))
            else:
                return self._stop(malformed, SourceExecutionReport('partial', 'provider-limit'))
        return self._stop(malformed)

    @staticmethod
    def _mentions_domain(entry: dict[str, Any], domain: str, title: str) -> bool:
        # The search matches free text, so a record whose website is another domain only mentions the target.
        website = SearchDarkEye._clean(entry.get('website')).casefold()
        if website:
            return website == domain or website.endswith(f'.{domain}')
        return domain in title.casefold()

    async def search_breach_house(self, domain: str) -> SourceExecutionReport | None:
        headers = {'Accept': 'application/json', 'Authorization': f'Bearer {self.breach_house_key}'}
        per_source = self.BREACH_HOUSE_MAX_LIMIT if self.limit is None else min(max(self.limit, 1), self.BREACH_HOUSE_MAX_LIMIT)
        url = f'{self.BREACH_HOUSE_URL}?{urlencode({"q": domain, "limit": per_source})}'
        malformed = False
        truncated = False
        async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy, request_timeout=60) as session:
            response = await AsyncFetcher.fetch_json(url, session=session)
        if failure := provider_http_error(response):
            logger.info('DarkEye %s request failed: %s', self.BREACH_HOUSE_PRODUCT, failure[1])
            return SourceExecutionReport(*failure)
        body = response.body
        if not isinstance(body, dict) or not any(source in body for source in self.BREACH_HOUSE_CATEGORIES):
            return SourceExecutionReport('failed', 'invalid-response')

        for source, category in self.BREACH_HOUSE_CATEGORIES.items():
            if source not in body:
                continue
            # Each source is {"results": [...], "total": n}.
            results = body[source].get('results') if isinstance(body[source], dict) else None
            total = body[source].get('total') if isinstance(body[source], dict) else None
            if not isinstance(results, list):
                malformed = True
                continue
            if isinstance(total, int) and not isinstance(total, bool) and total > len(results):
                truncated = True
            for entry in results:
                if not isinstance(entry, dict):
                    malformed = True
                    continue
                title = self._clean(entry.get('post_title')) or self._clean(entry.get('website'))
                if title and not self._mentions_domain(entry, domain, title):
                    continue
                added = self._add(self.BREACH_HOUSE_PRODUCT, category, entry)
                if added is None:
                    return self._stop(malformed, SourceExecutionReport('completed', 'result-limit'))
                malformed = malformed or not added
        if truncated:
            if self._limit_reached():
                return self._stop(malformed, SourceExecutionReport('completed', 'result-limit'))
            return self._stop(malformed, SourceExecutionReport('partial', 'provider-limit'))
        return self._stop(malformed)

    @staticmethod
    def _stop(malformed: bool, report: SourceExecutionReport | None = None) -> SourceExecutionReport | None:
        # Entries that could not be read take precedence, so the run is not reported as complete.
        return SourceExecutionReport('failed', 'invalid-response') if malformed else report

    async def get_breach_names(self) -> set[str]:
        return self.breach_names

    async def _run(self, search: Any, domain: str) -> SourceExecutionReport | None:
        try:
            return await search(domain)
        except ResponseStreamError as error:
            return SourceExecutionReport('failed', error.reason)
        except asyncio.CancelledError:
            raise
        except aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError:
            return SourceExecutionReport('failed', 'transport-error')

    async def process(self, proxy: bool | str = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        # Have I Been Ransomed? matches the domain field exactly, but treats * and ? as wildcards.
        try:
            domain = normalize_hostname(self.word)
        except ValueError:
            return SourceExecutionReport('failed', 'invalid-target')
        if '.' not in domain:
            return SourceExecutionReport('failed', 'invalid-target')

        reports: list[SourceExecutionReport] = []
        for key, search in ((self.hibr_key, self.search_hibr), (self.breach_house_key, self.search_breach_house)):
            if not key:
                continue
            report = await self._run(search, domain)
            if report is not None:
                reports.append(report)
            if report == SourceExecutionReport('completed', 'result-limit'):
                break
        # A product that failed is reported even when the other one completed, so the runner
        # can mark the run partial and keep the results already collected.
        for statuses in (('failed', 'rate-limited'), ('partial',), ('completed',)):
            for report in reports:
                if report.status in statuses:
                    return report
        return None
