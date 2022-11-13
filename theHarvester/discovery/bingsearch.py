from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser


class SearchBing:

    def __init__(self, word, limit, start) -> None:
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.total_results = ""
        self.server = 'www.bing.com'
        self.apiserver = 'api.search.live.net'
        self.hostname = 'www.bing.com'
        self.limit = int(limit)
        self.bingApi = Core.bing_key()
        self.counter = start
        self.proxy = False

    async def do_search(self) -> None:
        headers = {
            'Host': self.hostname,
            'Cookie': 'SRCHHPGUSR=ADLT=DEMOTE&NRSLT=50',
            'Accept-Language': 'en-us,en',
            'User-agent': Core.get_user_agent()
        }
        base_url = f'https://{self.server}/search?q=%40"{self.word}"&count=50&first=xx'
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 50) if num <= self.limit]
        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
        for response in responses:
            self.total_results += response

    async def do_search_api(self) -> None:
        url = 'https://api.cognitive.microsoft.com/bing/v7.0/search?'
        params = {
            'q': self.word,
            'count': str(self.limit),
            'offset': '0',
            'mkt': 'en-us',
            'safesearch': 'Off'
        }
        headers = {'User-Agent': Core.get_user_agent(), 'Ocp-Apim-Subscription-Key': self.bingApi}
        self.results = await AsyncFetcher.fetch_all([url], headers=headers, params=params, proxy=self.proxy)
        self.total_results += self.results

    async def do_search_vhost(self) -> None:
        headers = {
            'Host': self.hostname,
            'Cookie': 'mkt=en-US;ui=en-US;SRCHHPGUSR=NEWWND=0&ADLT=DEMOTE&NRSLT=50',
            'Accept-Language': 'en-us,en',
            'User-agent': Core.get_user_agent()
        }
        base_url = f'http://{self.server}/search?q=ip:{self.word}&go=&count=50&FORM=QBHL&qs=n&first=xx'
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 50) if num <= self.limit]
        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
        for response in responses:
            self.total_results += response

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()

    async def get_allhostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames_all()

    async def process(self, api, proxy: bool = False) -> None:
        self.proxy = proxy
        if api == 'yes':
            if self.bingApi is None:
                raise MissingKey('BingAPI')
        else:
            if api == 'yes':
                await self.do_search_api()
            else:
                await self.do_search()
            print(f'\tSearching {self.counter} results.')

    async def process_vhost(self) -> None:
        await self.do_search_vhost()
