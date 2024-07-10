from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchNetlas:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: list = []
        self.totalips: list = []
        self.key = Core.netlas_key()
        if self.key is None:
            raise MissingKey('netlas')
        self.proxy = False

    async def do_search(self) -> None:
        api = f'https://app.netlas.io/api/domains/?q=*.{self.word}&source_type=include&start=0&fields=*'
        headers = {'X-API-Key': self.key}
        response = await AsyncFetcher.fetch_all([api], json=True, headers=headers, proxy=self.proxy)
        for domain in response[0]['items']:
            self.totalhosts.append(domain['data']['domain'])

    async def get_hostnames(self) -> list:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
