import asyncio

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import securitytrailsparser


class SearchSecuritytrail:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.security_trails_key()
        if self.key is None:
            raise MissingKey('Securitytrail')
        self.results = ''
        self.totalresults = ''
        self.api = 'https://api.securitytrails.com/v1/'
        self.info: tuple[set, set] = (set(), set())
        self.proxy = False

    async def authenticate(self) -> None:
        # Method to authenticate API key before sending requests.
        headers = {'APIKEY': self.key}
        url = f'{self.api}ping'
        auth_responses = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
        auth_responses = auth_responses[0]
        if 'False' in auth_responses or 'Invalid authentication' in auth_responses:
            print('\tKey could not be authenticated exiting program.')
        await asyncio.sleep(5)

    async def do_search(self) -> None:
        try:
            # https://api.securitytrails.com/v1/domain/domain.com
            url = f'{self.api}domain/{self.word}'
            headers = {'APIKEY': self.key}
            response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
            await asyncio.sleep(5)  # Not random delay because 2 seconds is required due to rate limit.
            
            if response and response[0]:
                self.results = response[0]
                self.totalresults += self.results
            else:
                print('SecurityTrails: No response received for domain query')
                return
                
            url += '/subdomains'  # Get subdomains now.
            subdomain_response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
            await asyncio.sleep(5)
            
            if subdomain_response and subdomain_response[0]:
                self.results = subdomain_response[0]
                self.totalresults += self.results
            else:
                print('SecurityTrails: No response received for subdomain query')
        except Exception as e:
            print(f'SecurityTrails API error: {e}')
            return

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.authenticate()
        await self.do_search()
        parser = securitytrailsparser.Parser(word=self.word, text=self.totalresults)
        self.info = await parser.parse_text()
        # Create parser and set self.info to tuple returned from parsing text.
        print('\tDone Searching Results')

    async def get_ips(self) -> set:
        return self.info[0]

    async def get_hostnames(self) -> set:
        return self.info[1]
