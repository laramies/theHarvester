from theHarvester.lib.core import *


class SearchBeVigil:

    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.interestingurls = set()
        self.key = Core.bevigil_key()
        self.proxy = False

    async def do_search(self):
        subdomain_endpoint = f"https://osint.bevigil.com/api/{self.word}/subdomains/"
        url_endpoint = f"https://osint.bevigil.com/api/{self.word}/urls/"
        headers = {'X-Access-Token': self.key}

        responses = await AsyncFetcher.fetch_all([subdomain_endpoint], json=True, proxy=self.proxy, headers=headers)
        response = responses[0]
        for subdomain in response["subdomains"]:
            self.totalhosts.add(subdomain)

        responses = await AsyncFetcher.fetch_all([url_endpoint], json=True, proxy=self.proxy, headers=headers)
        response = responses[0]
        for url in response["urls"]:
            self.interestingurls.add(url)

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_interestingurls(self) -> set:
        return self.interestingurls

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
