import logging

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse

logger = logging.getLogger(__name__)


class SubdomainCenter:
    def __init__(self, word):
        self.word = word
        self.results = set()
        self.server = 'https://api.subdomain.center/?domain='
        self.proxy = False

    async def do_search(self):
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            current_url = f'{self.server}{self.word}'
            responses: list[FetcherResponse | None] = await AsyncFetcher.fetch_all(
                [current_url],
                headers=headers,
                proxy=self.proxy,
                json=True,
                include_metadata=True,
            )
            response = responses[0] if responses else None
            if response is None:
                logger.info('SubdomainCenter request failed')
                return
            if not 200 <= response.status < 300:
                logger.info(f'SubdomainCenter request failed with HTTP {response.status}')
                return
            payload = response.body
            self.results = (
                {hostname for hostname in payload if isinstance(hostname, str) and hostname.strip()}
                if isinstance(payload, list)
                else set()
            )
        except Exception as e:
            logger.info(f'An exception has occurred in SubdomainCenter on : {e}')

    async def get_hostnames(self):
        return self.results

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
