from theHarvester.lib.core import *
from typing import Set


class SearchCrtsh:

    def __init__(self, word):
        self.word = word
        self.data = set()
        self.proxy = False

    async def do_search(self) -> Set:
        data: set = set()
        try:
            url = f'https://crt.sh/?q=%25.{self.word}&output=json'
            response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
            response = response[0]
            data = set(
                [dct['name_value'][2:] if '*.' == dct['name_value'][:2] else dct['name_value']
                 for dct in response])
        except Exception as e:
            print(e)
        return data

    async def process(self, proxy=False) -> None:
        self.proxy = proxy
        print('\tSearching results.')
        data = await self.do_search()
        self.data = data

    async def get_data(self) -> Set:
        return self.data
