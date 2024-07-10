import asyncio

import aiohttp

from theHarvester.lib.core import Core
from theHarvester.parsers import myparser


class SearchDnsDumpster:
    def __init__(self, word) -> None:
        self.word = word.replace(' ', '%20')
        self.results = ''
        self.totalresults = ''
        self.server = 'dnsdumpster.com'
        self.proxy = False

    async def do_search(self) -> None:
        try:
            agent = Core.get_user_agent()
            headers = {'User-Agent': agent}
            session = aiohttp.ClientSession(headers=headers)
            # create a session to properly verify
            url = f'https://{self.server}'
            csrftoken = ''
            if self.proxy is False:
                async with session.get(url, headers=headers) as resp:
                    resp_cookies = str(resp.cookies)
                    cookies = resp_cookies.split('csrftoken=')
                    csrftoken += cookies[1][: cookies[1].find(';')]
            else:
                async with session.get(url, headers=headers, proxy=self.proxy) as resp:
                    resp_cookies = str(resp.cookies)
                    cookies = resp_cookies.split('csrftoken=')
                    csrftoken += cookies[1][: cookies[1].find(';')]
            await asyncio.sleep(5)

            # extract csrftoken from cookies
            data = {
                'Cookie': f'csfrtoken={csrftoken}',
                'csrfmiddlewaretoken': csrftoken,
                'targetip': self.word,
                'user': 'free',
            }
            headers['Referer'] = url
            if self.proxy is False:
                async with session.post(url, headers=headers, data=data) as resp:
                    self.results = await resp.text()
            else:
                async with session.post(url, headers=headers, data=data, proxy=self.proxy) as resp:
                    self.results = await resp.text()
            await session.close()
        except Exception as e:
            print(f'An exception occurred: {e}')
        self.totalresults += self.results

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()  # Only need to do it once.
