from theHarvester.lib.core import *
from bs4 import BeautifulSoup
import requests
import aiohttp
import asyncio


class SearchSuip:

    def __init__(self, word: str):
        self.word: str = word
        self.results: str = ''
        self.totalresults: str = ''
        self.totalhosts: set = set()
        self.totalips: set = set()

    async def request(self, url, params):
        headers = {'User-Agent': Core.get_user_agent()}
        data = {'url': self.word.replace('www.', ''), 'Submit1': 'Submit'}
        timeout = aiohttp.ClientTimeout(total=360)
        # by default timeout is 5 minutes we will change that to 6 minutes
        # Depending on the domain and if it has a lot of subdomains you may want to tweak it
        # The results are well worth the wait :)
        try:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                async with session.post(url, params=params, data=data) as resp:
                    await asyncio.sleep(3)
                    return await resp.text()
        except Exception as e:
            print(f'An exception has occurred: {e}')
            return ''

    async def handler(self, url):
        first_data = [url, (('act', 'subfinder'),), ]
        second_data = [url, (('act', 'amass'),), ]
        # TODO RESEARCH https://suip.biz/?act=findomain
        async_requests = [
            self.request(url=url, params=params)
            for url, params in [first_data, second_data]
        ]
        results = await asyncio.gather(*async_requests)
        return results

    async def do_search(self):
        try:
            results = await self.handler(url="https://suip.biz/")
            for result in results:
                # results has both responses in a list
                # iterate through them and parse out the urls
                soup = BeautifulSoup(str(result), 'html.parser')
                hosts: list = str(soup.find('pre')).splitlines()
                await self.clean_hosts(hosts)
        except Exception as e:
            print('An exception has occurred: ', e)
            import traceback as t
            t.print_exc()

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self):
        await self.do_search()
        print('\tSearching results.')

    async def clean_hosts(self, soup_hosts):
        for host in soup_hosts:
            host = str(host).strip()
            if len(host) > 1 and 'pre' not in host:
                if host[0] == '.':
                    self.totalhosts.add(host[1:])
                else:
                    self.totalhosts.add(host)
