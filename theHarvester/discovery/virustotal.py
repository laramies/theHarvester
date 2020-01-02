from theHarvester.lib.core import *
from theHarvester.parsers import myparser


class SearchVirustotal:

    def __init__(self, word):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.quantity = '100'
        self.counter = 0

    async def do_search(self):
        base_url = f'https://www.virustotal.com/ui/domains/{self.word}/subdomains?relationships=resolutions&cursor=STMwCi4%3D&limit=40'
        headers = {'User-Agent': Core.get_user_agent()}
        responses = await AsyncFetcher.fetch_all([base_url], headers=headers)
        self.results = responses[0]
        self.totalresults += self.results

    async def get_hostnames(self):
        rawres = myparser.Parser(self.results, self.word)
        return await rawres.hostnames()

    async def process(self):
        print('\tSearching results.')
        await self.do_search()
