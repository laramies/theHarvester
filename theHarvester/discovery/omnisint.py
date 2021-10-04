import requests
import json
from theHarvester.lib.core import *


class SearchOmnisint:
    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.proxy = False

    async def do_search(self):
        base_url = f'https://sonar.omnisint.io/all/{self.word}?page=1'
        data = requests.get(base_url, headers={'User-Agent': Core.get_user_agent()}).text
        entries = json.loads(data)
        self.totalhosts = entries

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
