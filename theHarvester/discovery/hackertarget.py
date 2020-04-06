from theHarvester.lib.core import *


class SearchHackerTarget:
    """
    Class uses the HackerTarget api to gather subdomains and ips
    """
    def __init__(self, word):
        self.word = word
        self.total_results = ""
        self.hostname = 'https://api.hackertarget.com'
        self.proxy = False
        self.results = None

    async def do_search(self):
        headers = {'User-agent': Core.get_user_agent()}
        urls = [f'{self.hostname}/hostsearch/?q={self.word}', f'{self.hostname}/reversedns/?q={self.word}']
        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
        for response in responses:
            self.total_results += response.replace(",", ":")

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()

    async def get_hostnames(self) -> list:
        return self.total_results.splitlines()
