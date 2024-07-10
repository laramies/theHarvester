from theHarvester.lib.core import AsyncFetcher, Core


class SubdomainCenter:
    def __init__(self, word):
        self.word = word
        self.results = set()
        self.server = 'https://api.subdomain.center/?domain='
        self.proxy = False

    async def do_search(self):
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            current_url = f'{self.server}{self.word}'
            resp = await AsyncFetcher.fetch_all([current_url], headers=headers, proxy=self.proxy, json=True)
            self.results = resp[0]
            self.results = {sub[4:] if sub[:4] == 'www.' and sub[4:] else sub for sub in self.results}
        except Exception as e:
            print(f'An exception has occurred in SubdomainCenter on : {e}')

    async def get_hostnames(self):
        return self.results

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
