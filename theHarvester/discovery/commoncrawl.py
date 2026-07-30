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
    PAGE_BATCH_SIZE = 10

    def __init__(self, word) -> None:
        self.word = word.lower().rstrip('.')
        self.totalhosts: set[str] = set()
        self.proxy = False
        self.hostname = 'https://index.commoncrawl.org'

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

    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        if not url:
            return ''

        parsed = urlsplit(url if '://' in url else f'//{url}')
        return (parsed.hostname or '').lower().rstrip('.')

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
                timestamp = datetime.fromisoformat(str(entry['to'])).replace(tzinfo=None)
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
            headers = {'User-agent': Core.get_user_agent()}
            catalog_response = await AsyncFetcher.fetch_all(
                [f'{self.hostname}/collinfo.json'], headers=headers, proxy=self.proxy, json=True
            )
            if not catalog_response or not isinstance(catalog_response[0], list) or not catalog_response[0]:
                logger.error('Common Crawl API error: invalid index catalog')
                return

            indexes = self._select_indexes(catalog_response[0])
            if not indexes:
                logger.error('Common Crawl API error: index catalog contains no usable entries')
                return

            successful_queries = 0
            for index in indexes:
                endpoint = index['cdx-api']
                for query in (f'*.{self.word}', f'{self.word}/*'):
                    try:
                        count_url = f'{endpoint}?{urlencode({"url": query, "output": "json", "pageSize": self.PAGE_SIZE, "showNumPages": "true"})}'
                        count_response = await AsyncFetcher.fetch_all([count_url], headers=headers, proxy=self.proxy)
                        count_payload = json.loads(count_response[0])
                        page_count = count_payload.get('pages') if isinstance(count_payload, dict) else None
                        if isinstance(page_count, bool) or not isinstance(page_count, int) or page_count < 0:
                            raise ValueError('invalid page count')
                        query_succeeded = page_count == 0
                        for first_page in range(0, page_count, self.PAGE_BATCH_SIZE):
                            page_urls = [
                                f'{endpoint}?{urlencode({"url": query, "output": "json", "pageSize": self.PAGE_SIZE, "page": page})}'
                                for page in range(first_page, min(first_page + self.PAGE_BATCH_SIZE, page_count))
                            ]
                            responses = await AsyncFetcher.fetch_all(page_urls, headers=headers, proxy=self.proxy)
                            if not isinstance(responses, list) or not responses:
                                raise ValueError('invalid page batch')
                            for response in responses:
                                try:
                                    if not response:
                                        raise ValueError('empty page response')
                                    for record in self._safe_parse_json_lines(response):
                                        if isinstance(record, dict):
                                            domain = self._extract_domain_from_url(record.get('url', ''))
                                            if domain.endswith(f'.{self.word}') or domain == self.word:
                                                self.totalhosts.add(domain)
                                    query_succeeded = True
                                except ValueError as error:
                                    logger.warning(f'Common Crawl page error for index {index.get("id", "unknown")}: {error}')
                                except Exception:
                                    logger.warning(
                                        f'Common Crawl page error for index {index.get("id", "unknown")}: unexpected page failure'
                                    )
                        if query_succeeded:
                            successful_queries += 1
                    except Exception as error:
                        logger.warning(f'Common Crawl API error for index {index.get("id", "unknown")}: {error}')

            if not successful_queries and not self.totalhosts:
                raise RuntimeError('all Common Crawl queries failed')

        except RuntimeError:
            raise
        except Exception as error:
            logger.error(f'Common Crawl API error: {error}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
