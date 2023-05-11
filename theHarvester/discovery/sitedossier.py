from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests


class SearchSitedossier:

    def __init__(self, word):
        self.word = word
        self.totalresults = ""
        self.server = "www.sitedossier.com"
        self.limit = 50

    async def do_search(self):
        url = f"http://{self.server}/parentdomain/{self.word}"
        headers = {'User-Agent': Core.get_user_agent()}

        response = requests.get(url, headers=headers)
        self.totalresults += response.text

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
