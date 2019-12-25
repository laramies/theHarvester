from theHarvester.lib.core import *
import aiohttp


class SearchCrtsh:

    def __init__(self, word):
        self.word = word
        self.data = set()

    async def do_search(self) -> Set:
        data: set = set()
        try:
            url = f'https://crt.sh/?q=%25.{self.word}&output=json'
            headers = {'User-Agent': Core.get_user_agent()}
            client = aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=20))
            response = await AsyncFetcher.fetch(client, url, json=True)
            await client.close()
            data = set(
                [dct['name_value'][2:] if '*.' == dct['name_value'][:2] else dct['name_value'] for dct in response])
        except Exception as e:
            print(e)
        return data

    async def process(self) -> None:
        print('\tSearching results.')
        data = await self.do_search()
        self.data = data

    async def get_data(self) -> Set:
        return self.data
