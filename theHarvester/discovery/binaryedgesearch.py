from theHarvester.discovery.constants import *
from typing import Set
import asyncio


class SearchBinaryEdge:

    def __init__(self, word, limit) -> None:
        self.word = word
        self.totalhosts: Set = set()
        self.proxy = False
        self.key = Core.binaryedge_key()
        self.limit = 501 if limit >= 501 else limit
        self.limit = 2 if self.limit == 1 else self.limit
        if self.key is None:
            raise MissingKey('binaryedge')

    async def do_search(self) -> None:
        base_url = f'https://api.binaryedge.io/v2/query/domains/subdomain/{self.word}'
        headers = {'X-KEY': self.key, 'User-Agent': Core.get_user_agent()}
        for page in range(1, self.limit):
            params = {'page': page}
            response = await AsyncFetcher.fetch_all([base_url], json=True, proxy=self.proxy, params=params, headers=headers)
            responses = response[0]
            dct = responses
            if ('status' in dct.keys() and 'message' in dct.keys()) and \
                    (dct['status'] == 400 or 'Bad Parameter' in dct['message'] or 'Error' in dct['message']):
                # 400 status code means no more results
                break
            if 'events' in dct.keys():
                if len(dct['events']) == 0:
                    break
                self.totalhosts.update({host for host in dct['events']})
            await asyncio.sleep(get_delay())

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
