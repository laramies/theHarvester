from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import securitytrailsparser
from typing import NoReturn
import asyncio


class SearchSecuritytrail:

    def __init__(self, word):
        self.word = word
        self.key = Core.security_trails_key()
        if self.key is None:
            raise MissingKey(True)
        self.results = ""
        self.totalresults = ""
        self.api = 'https://api.securitytrails.com/v1/'
        self.info = ()

    async def authenticate(self) -> NoReturn:
        # Method to authenticate API key before sending requests.
        headers = {'APIKEY': self.key}
        url = f'{self.api}ping'
        auth_responses = await AsyncFetcher.fetch_all([url], headers=headers)
        if 'False' in auth_responses or 'Invalid authentication' in auth_responses:
            print('\tKey could not be authenticated exiting program.')
        await asyncio.sleep(2)

    async def do_search(self):
        url = ''
        headers = {}
        # https://api.securitytrails.com/v1/domain/domain.com
        url = f'{self.api}domain/{self.word}'
        headers = {'APIKEY': self.key}
        responses = await AsyncFetcher.fetch_all([url], headers=headers)
        await asyncio.sleep(2)  # Not random delay because 2 seconds is required due to rate limit.

        self.results = responses[0]
        print(responses)
        self.totalresults += self.results
        url += '/subdomains'  # Get subdomains now.
        subdomain_responses = await AsyncFetcher.fetch_all([url], headers=headers)
        await asyncio.sleep(2)
        print(subdomain_responses)
        self.results = subdomain_responses
        self.totalresults += self.results

    async def process(self) -> NoReturn:
        await self.authenticate()
        await self.do_search()
        parser = securitytrailsparser.Parser(word=self.word, text=self.totalresults)
        self.info = await parser.parse_text()
        # Create parser and set self.info to tuple returned from parsing text.
        print('\tDone Searching Results')

    async def get_ips(self):
        return await self.info[0]

    async def get_hostnames(self):
        return await self.info[1]
