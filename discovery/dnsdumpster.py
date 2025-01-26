import aiohttp
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core, AsyncFetcher


class SearchDnsDumpster:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.dnsdumpster_key()
        if self.key is None:
            raise MissingKey('dnsdumpster')
        self.total_results = None
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://api.dnsdumpster.com/domain/{self.word}'
        headers = {
            'User-Agent': Core.get_user_agent(),
            'X-API-Key': self.key
        }
        try:
            responses = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
            response = responses[0]
            if response.status == 200:
                json_response = await response.json()
                self.total_results = json_response.get('a', [])
            else:
                print(f"Error: Received status code {response.status}")
        except Exception as e:
            print(f"An exception occurred in DNSdumpster: {e}")

    async def get_hostnames(self):
        return [entry['host'] for entry in self.total_results]

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
