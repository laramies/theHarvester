from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from pprint import pprint


class SearchSpyse:

    def __init__(self, word):
        self.word = word
        self.key = Core.spyse_key()
        if self.key is None:
            raise MissingKey(True)
        self.totalhosts = set()

    async def do_search(self):
        try:
            url = f'https://api.spyse.com/v1/subdomains-aggregate?domain={self.word}&api_token={self.key}'
            headers = {'User-Agent': Core.get_user_agent()}
            client = aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=30))
            responses = await AsyncFetcher.fetch(client, url, json=True)
            await client.close()

            dct = responses['cidr']['cidr16']['results']['data']
            pprint(dct, indent=4)


        except Exception as e:
            print(f'An exception has occurred: {e}')

    # async def get_hostnames(self):
    #     return self.totalhosts

    async def process(self):
        await self.do_search()
