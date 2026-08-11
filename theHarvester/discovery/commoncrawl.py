import asyncio
import json as _stdlib_json
import logging
from datetime import datetime, timedelta
from types import ModuleType
from urllib.parse import urlencode, urlsplit

from theHarvester.lib.core import AsyncFetcher, Core

logger = logging.getLogger(__name__)

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError:
    pass
except Exception:
    pass


class SearchCommoncrawl:
    """Gather subdomains from every crawl ending within one year of the newest catalog entry.

    API docs: https://commoncrawl.org/get-started
    Index catalog: https://index.commoncrawl.org/collinfo.json
    """

    INDEX_LOOKBACK = timedelta(days=365)
    PAGE_SIZE = 5
    MAX_RECORDS_PER_REQUEST = 50
    MAX_CONSECUTIVE_PAGE_ERRORS = 3
    RUNTIME_SECONDS = 120.0
    # Protect the shared index service even when its page count is unexpectedly large.
    MAX_PAGES_PER_QUERY = 100

    def __init__(self, word, limit: int = 500) -> None:
        self.word = word.lower().rstrip('.')
        self.limit = max(limit, 0)
        self.totalhosts: set[str] = set()
        self.proxy = False
        self.hostname = 'https://index.commoncrawl.org'
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    @staticmethod
    def _safe_parse_json_lines(payload: str) -> list:
        """Parse JSON lines format"""
        results: list = []
        malformed = False
        if not payload:
            return results
        if payload.lstrip().startswith('<'):
            raise ValueError('unexpected non-JSON response')

        for line in payload.strip().split('\n'):
            if line.strip():
                try:
                    results.append(json.loads(line))
                except Exception:
                    malformed = True
        if malformed:
            if not results:
                raise ValueError('malformed JSON line')
            logger.warning('Common Crawl response contained a malformed JSON line; valid records were preserved')
        return results

    def _extract_domain_from_url(self, url: object) -> str:
        """Extract domain from URL"""
        if not isinstance(url, str) or not url:
            return ''

        try:
            parsed = urlsplit(url if '://' in url else f'//{url}')
            return (parsed.hostname or '').lower().rstrip('.')
        except ValueError:
            return ''

    @classmethod
    def _select_indexes(cls, catalog: list[object]) -> list[dict]:
        dated_indexes: list[tuple[datetime, dict]] = []
        for entry in catalog:
            if not isinstance(entry, dict):
                logger.warning('Common Crawl API error for index unknown: invalid catalog entry')
                continue
            index_id = entry.get('id', 'unknown')
            endpoint = entry.get('cdx-api')
            if not isinstance(endpoint, str):
                logger.warning(f'Common Crawl API error for index {index_id}: invalid catalog entry')
                continue
            parsed_endpoint = urlsplit(endpoint)
            if (
                parsed_endpoint.scheme != 'https'
                or parsed_endpoint.netloc != 'index.commoncrawl.org'
                or not parsed_endpoint.path.startswith('/CC-MAIN-')
                or not parsed_endpoint.path.endswith('-index')
                or parsed_endpoint.query
                or parsed_endpoint.fragment
            ):
                logger.warning(f'Common Crawl API error for index {index_id}: invalid catalog entry')
                continue
            try:
                timestamp = datetime.fromisoformat(str(entry.get('to'))).replace(tzinfo=None)
            except (KeyError, ValueError):
                logger.warning(f'Common Crawl API error for index {index_id}: invalid catalog entry')
                continue
            dated_indexes.append((timestamp, entry))

        if not dated_indexes:
            return []

        cutoff = max(timestamp for timestamp, _ in dated_indexes) - cls.INDEX_LOOKBACK
        selected: list[dict] = []
        endpoints: set[str] = set()
        for timestamp, entry in sorted(dated_indexes, key=lambda item: item[0], reverse=True):
            endpoint = entry['cdx-api']
            if timestamp >= cutoff and endpoint not in endpoints:
                endpoints.add(endpoint)
                selected.append(entry)
        return selected

    async def do_search(self) -> None:
        try:
            self.execution_status = None
            self.stop_reason = None
            if self.limit == 0:
                return

            headers = {'User-agent': Core.get_user_agent()}
            catalog_response = await AsyncFetcher.fetch_all(
                [f'{self.hostname}/collinfo.json'], headers=headers, proxy=self.proxy, json=True
            )
            if not catalog_response or not isinstance(catalog_response[0], list) or not catalog_response[0]:
                self.execution_status = 'failed'
                self.stop_reason = 'invalid-catalog'
                logger.error('Common Crawl API error: invalid index catalog')
                return

            indexes = self._select_indexes(catalog_response[0])
            if not indexes:
                self.execution_status = 'failed'
                self.stop_reason = 'no-usable-indexes'
                logger.error('Common Crawl API error: index catalog contains no usable entries')
                return

            query_total = len(indexes) * 2
            logger.info(
                'Common Crawl selected %d %s and %d queries',
                len(indexes),
                'index' if len(indexes) == 1 else 'indexes',
                query_total,
            )

            successful_queries = 0
            failed_queries = 0
            page_limit_reached = False
            query_number = 0
            for index in indexes:
                endpoint = index['cdx-api']
                for query in (f'*.{self.word}', f'{self.word}/*'):
                    query_number += 1
                    logger.info(
                        'Common Crawl query %d/%d: index=%s',
                        query_number,
                        query_total,
                        index.get('id', 'unknown'),
                    )
                    query_succeeded = False
                    try:
                        query_had_errors = False
                        count_url = f'{endpoint}?{urlencode({"url": query, "output": "json", "pageSize": self.PAGE_SIZE, "showNumPages": "true"})}'
                        count_response = await AsyncFetcher.fetch_all([count_url], headers=headers, proxy=self.proxy)
                        count_payload = json.loads(count_response[0])
                        page_count = count_payload.get('pages') if isinstance(count_payload, dict) else None
                        if isinstance(page_count, bool) or not isinstance(page_count, int) or page_count < 0:
                            raise ValueError('invalid page count')
                        query_succeeded = page_count == 0
                        page_limit = min(page_count, self.MAX_PAGES_PER_QUERY)
                        first_page = 0
                        consecutive_page_errors = 0
                        while first_page < page_limit:
                            remaining = self.limit - len(self.totalhosts)
                            if remaining == 0:
                                return
                            page_url = f'{endpoint}?{urlencode({"url": query, "output": "json", "pageSize": self.PAGE_SIZE, "page": first_page, "limit": min(remaining, self.MAX_RECORDS_PER_REQUEST)})}'
                            first_page += 1
                            responses = await AsyncFetcher.fetch_all([page_url], headers=headers, proxy=self.proxy)
                            if not isinstance(responses, list) or not responses:
                                raise ValueError('invalid page response')
                            try:
                                response = responses[0]
                                if not response:
                                    raise ValueError('empty page response')
                                for record in self._safe_parse_json_lines(response):
                                    if isinstance(record, dict):
                                        domain = self._extract_domain_from_url(record.get('url', ''))
                                        if domain.endswith(f'.{self.word}') or domain == self.word:
                                            self.totalhosts.add(domain)
                                            if len(self.totalhosts) >= self.limit:
                                                return
                            except ValueError as error:
                                message = str(error)
                            except Exception:
                                message = 'unexpected page failure'
                            else:
                                query_succeeded = True
                                consecutive_page_errors = 0
                                continue
                            query_had_errors = True
                            logger.warning(f'Common Crawl page error for index {index.get("id", "unknown")}: {message}')
                            consecutive_page_errors += 1
                            if consecutive_page_errors >= self.MAX_CONSECUTIVE_PAGE_ERRORS:
                                break
                        if page_count > page_limit:
                            page_limit_reached = True
                            logger.warning(
                                f'Common Crawl page limit reached for index {index.get("id", "unknown")}; '
                                'results may be incomplete'
                            )
                        if query_had_errors:
                            failed_queries += 1
                    except Exception as error:
                        failed_queries += 1
                        logger.warning(f'Common Crawl API error for index {index.get("id", "unknown")}: {error}')
                    if query_succeeded:
                        successful_queries += 1

            if failed_queries:
                if successful_queries or self.totalhosts:
                    self.execution_status = 'partial'
                    self.stop_reason = 'query-errors'
                else:
                    self.execution_status = 'failed'
                    self.stop_reason = 'all-queries-failed'
                    logger.warning(f'Common Crawl failed all {query_total} queries')
            elif page_limit_reached:
                self.execution_status = 'partial'
                self.stop_reason = 'page-limit'

        except Exception as error:
            self.execution_status = 'partial' if self.totalhosts else 'failed'
            self.stop_reason = 'unexpected-error'
            logger.error(f'Common Crawl API error: {error}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        try:
            async with asyncio.timeout(self.RUNTIME_SECONDS):
                await self.do_search()
        except TimeoutError:
            self.execution_status = 'partial' if self.totalhosts else 'failed'
            self.stop_reason = 'runtime-limit'
            logger.info(
                f'Common Crawl runtime limit reached after {self.RUNTIME_SECONDS:g}s; preserved {len(self.totalhosts)} hosts'
            )
