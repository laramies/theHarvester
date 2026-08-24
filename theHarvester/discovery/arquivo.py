import asyncio
import json
import logging
from urllib.parse import urlencode, urlsplit

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchArquivo:
    PAGE_SIZE = 10_000

    def __init__(self, word: str, limit: int | None) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.limit = limit
        self.totalhosts: set[str] = set()
        self.proxy = False

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        offset = 0
        previous_page = None
        report = None
        while self.limit is None or offset < self.limit:
            page_size = self.PAGE_SIZE if self.limit is None else min(self.PAGE_SIZE, self.limit - offset)
            parameters = {
                'url': self.word,
                'matchType': 'domain',
                'output': 'json',
                'fields': 'url',
                'limit': page_size,
            }
            if offset:
                parameters['offset'] = offset
            query = urlencode(parameters)
            try:
                responses: list[FetcherResponse | None] = await AsyncFetcher.fetch_all(
                    [f'https://arquivo.pt/wayback/cdx?{query}'],
                    headers={'User-agent': Core.get_user_agent()},
                    proxy=self.proxy,
                    include_metadata=True,
                )
            except asyncio.CancelledError:
                raise
            except Exception as error:
                logger.info(f'Arquivo.pt request failed: {error}')
                return SourceExecutionReport('partial' if self.totalhosts else 'failed', 'transport-error')

            response = responses[0] if responses else None
            if response is None:
                logger.info('Arquivo.pt request failed')
                return SourceExecutionReport('partial' if self.totalhosts else 'failed', 'transport-error')
            if not 200 <= response.status < 300:
                logger.info(f'Arquivo.pt request failed with HTTP {response.status}')
                return SourceExecutionReport('partial' if self.totalhosts else 'failed', f'http-{response.status}')
            if not isinstance(response.body, str):
                logger.info('Arquivo.pt returned malformed CDX data')
                return SourceExecutionReport('partial' if self.totalhosts else 'failed', 'invalid-response')
            if response.body == previous_page:
                return SourceExecutionReport('partial', 'repeated-page')
            previous_page = response.body

            lines = response.body.splitlines()
            malformed = False
            for line in lines:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError, TypeError:
                    malformed = True
                    continue
                if not isinstance(item, dict) or not isinstance(url := item.get('url'), str):
                    malformed = True
                    continue
                try:
                    hostname = urlsplit(url).hostname
                except ValueError:
                    malformed = True
                    continue
                if (normalized := normalize_scoped_hostname(hostname, self.word)) and normalized != self.word:
                    self.totalhosts.add(normalized)
            if malformed:
                report = SourceExecutionReport('partial' if self.totalhosts else 'failed', 'invalid-response')
            offset += len(lines)
            if len(lines) < page_size:
                break
        if report is not None and self.totalhosts and report.status == 'failed':
            return SourceExecutionReport('partial', report.stop_reason)
        return report

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts
