import logging

from theHarvester.lib.core import AsyncFetcher, Core

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
            resp = await AsyncFetcher.fetch_all([current_url], headers=headers, proxy=self.proxy, json=True)
            payload = resp[0] if resp else []
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
