from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import aiohttp
import asyncio


class SearchDnsDumpster:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'dnsdumpster.com'

    async def do_search(self):
        try:
            agent = Core.get_user_agent()
            headers = {'User-Agent': agent}
            session = aiohttp.ClientSession(headers=headers)
            # create a session to properly verify
            url = f'https://{self.server}'
            csrftoken = ''
            async with session.get(url, headers=headers) as resp:
                cookies = str(resp.cookies)
                cookies = cookies.split('csrftoken=')
                csrftoken += cookies[1][:cookies[1].find(';')]
            await asyncio.sleep(2)
            # extract csrftoken from cookies
            data = {
                'Cookie': f'csfrtoken={csrftoken}', 'csrfmiddlewaretoken': csrftoken, 'targetip': self.word}
            headers['Referer'] = url
            async with session.post(url, headers=headers, data=data) as resp:
                self.results = await resp.text()
            await session.close()
        except Exception as e:
            print(f'An exception occured: {e}')
        self.totalresults += self.results

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    async def process(self):
        await self.do_search()  # Only need to do it once.
