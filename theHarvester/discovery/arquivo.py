import json
import logging
from urllib.parse import urlencode, urlsplit

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname

logger = logging.getLogger(__name__)


class SearchArquivo:
    MAX_RESULTS = 10_000

    def __init__(self, word: str, limit: int) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.limit = min(max(limit, 1), self.MAX_RESULTS)
        self.totalhosts: set[str] = set()
        self.proxy = False

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        query = urlencode(
            {
                'url': self.word,
                'matchType': 'domain',
                'output': 'json',
                'fields': 'url',
                'limit': self.limit,
            }
        )
        try:
            responses: list[FetcherResponse | None] = await AsyncFetcher.fetch_all(
                [f'https://arquivo.pt/wayback/cdx?{query}'],
                headers={'User-agent': Core.get_user_agent()},
                proxy=self.proxy,
                include_metadata=True,
            )
        except Exception as error:
            logger.info(f'Arquivo.pt request failed: {error}')
            return

        response = responses[0] if responses else None
        if response is None:
            logger.info('Arquivo.pt request failed')
            return
        if not 200 <= response.status < 300:
            logger.info(f'Arquivo.pt request failed with HTTP {response.status}')
            return
        if not isinstance(response.body, str):
            logger.info('Arquivo.pt returned malformed CDX data')
            return

        for line in response.body.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError, TypeError:
                continue
            if not isinstance(item, dict) or not isinstance(url := item.get('url'), str):
                continue
            try:
                hostname = urlsplit(url).hostname
            except ValueError:
                continue
            if (normalized := normalize_scoped_hostname(hostname, self.word)) and normalized != self.word:
                self.totalhosts.add(normalized)

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts
