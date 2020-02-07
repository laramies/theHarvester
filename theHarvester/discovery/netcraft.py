from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import hashlib
import urllib.parse as urllib
import re
import aiohttp
import asyncio
import random


class SearchNetcraft:
    # this module was inspired by sublist3r's netcraft module

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.totalresults = ""
        self.server = 'netcraft.com'
        self.base_url = f'https://searchdns.netcraft.com/?restriction=site+ends+with&host={word}'
        self.session = None
        self.headers = {
            'User-Agent': Core.get_user_agent()
        }
        self.timeout = aiohttp.ClientTimeout(total=25)
        self.domain = f"https://searchdns.netcraft.com/?restriction=site+ends+with&host={self.word}"
        self.proxy = False

    async def request(self, url, first=False):
        try:
            if first:
                # indicates first request to extract cookie
                async with aiohttp.ClientSession(headers=self.headers, timeout=self.timeout) as sess:
                    if self.proxy:
                        async with sess.get(url, proxy=random.choice(Core.proxy_list())) as resp:
                            await asyncio.sleep(3)
                            return resp.headers
                    else:
                        async with sess.get(url) as resp:
                            await asyncio.sleep(3)
                            return resp.headers
            else:
                if self.proxy:
                    async with self.session.get(url, proxy=random.choice(Core.proxy_list())) as sess:
                        await asyncio.sleep(2)
                        return await sess.text()
                else:
                    async with self.session.get(url) as sess:
                        await asyncio.sleep(2)
                        return await sess.text()
        except Exception:
            resp = None
        return resp

    async def get_next(self, resp):
        link_regx = re.compile('<A href="(.*?)"><b>Next page</b></a>')
        link = link_regx.findall(resp)
        link = re.sub(f'host=.*?{self.word}', f'host={self.domain}', link[0])
        url = f'https://searchdns.netcraft.com{link.replace(" ", "%20")}'
        return url

    async def create_cookies(self, cookie):
        cookies = dict()
        cookies_list = cookie[0:cookie.find(';')].split("=")
        cookies[cookies_list[0]] = cookies_list[1]
        # get js verification response
        cookies['netcraft_js_verification_response'] = hashlib.sha1(
            urllib.unquote(cookies_list[1]).encode('utf-8')).hexdigest()
        return cookies

    async def get_cookies(self, headers):
        try:
            if headers is None:
                # In this case just return default dict
                return {}
            elif 'set-cookie' in headers:
                cookies = await self.create_cookies(headers['set-cookie'])
            else:
                cookies = {}
        except Exception:
            return {}
        return cookies

    async def do_search(self):
        try:
            start_url = self.base_url
            resp = await self.request(start_url, first=True)
            # indicates this is the start_url to retrieve cookie we need
            cookies = await self.get_cookies(resp)
            self.session = aiohttp.ClientSession(headers=self.headers, timeout=self.timeout, cookies=cookies)
            while True:
                resp = await self.request(self.base_url)
                if isinstance(resp, str):
                    self.totalresults += resp
                if 'Next page' not in resp or resp is None:
                    await self.session.close()
                    break
                self.base_url = await self.get_next(resp)
        except Exception:
            try:
                await self.session.close()
            except Exception:
                pass

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
