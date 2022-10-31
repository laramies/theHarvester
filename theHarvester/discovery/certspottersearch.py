from theHarvester.lib.core import *
from typing import Set


class SearchCertspoter:

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: Set = set()
        self.proxy = False

    async def do_search(self) -> None:
        base_url = f'https://api.certspotter.com/v1/issuances?domain={self.word}&expand=dns_names'
        try:
            response = await AsyncFetcher.fetch_all([base_url], json=True, proxy=self.proxy)
            response = response[0]
            if isinstance(response, list):
                for dct in response:
                    for key, value in dct.items():
                        if key == 'dns_names':
                            self.totalhosts.update({name for name in value if name})
            elif isinstance(response, dict):
                self.totalhosts.update({response['dns_names'] if 'dns_names' in response.keys() else ''})  # type: ignore
            else:
                self.totalhosts.update({''})
        except Exception as e:
            print(e)

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
        print('\tSearching results.')
