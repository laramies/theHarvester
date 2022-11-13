from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import json
from typing import Union


class SearchDuckDuckGo:

    def __init__(self, word, limit) -> None:
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.dorks: List = []
        self.links: List = []
        self.database = 'https://duckduckgo.com/?q='
        self.api = 'https://api.duckduckgo.com/?q=x&format=json&pretty=1'  # Currently using API.
        self.quantity = '100'
        self.limit = limit
        self.proxy = False

    async def do_search(self) -> None:
        # Do normal scraping.
        url = self.api.replace('x', self.word)
        headers = {'User-Agent': googleUA}
        first_resp = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
        self.results = first_resp[0]
        self.totalresults += self.results
        urls = await self.crawl(self.results)
        urls = {url for url in urls if len(url) > 5}
        all_resps = await AsyncFetcher.fetch_all(urls)
        self.totalresults += ''.join(all_resps)

    async def crawl(self, text: Union[bytes, str]):
        """
        Function parses json and returns URLs.
        :param text: formatted json
        :return: set of URLs
        """
        urls = set()
        try:
            load = json.loads(text)
            for keys in load.keys():  # Iterate through keys of dict.
                val = load.get(keys)
                if isinstance(val, int) or isinstance(val, dict) or val is None:
                    continue
                if isinstance(val, list):
                    if len(val) == 0:  # Make sure not indexing an empty list.
                        continue
                    val = val[0]  # The First value should be dict.
                    if isinstance(val, dict):  # Validation check.
                        for key in val.keys():
                            value = val.get(key)
                            if isinstance(value, str) and value != '' and 'https://' in value or 'http://' in value:
                                urls.add(value)
                if isinstance(val, str) and val != '' and 'https://' in val or 'http://' in val:
                    urls.add(val)
            tmp = set()
            for url in urls:
                if '<' in url and 'href=' in url:  # Format is <href="https://www.website.com"/>
                    equal_index = url.index('=')
                    true_url = ''
                    for ch in url[equal_index + 1:]:
                        if ch == '"':
                            tmp.add(true_url)
                            break
                        true_url += ch
                else:
                    if url != '':
                        tmp.add(url)
            return tmp
        except Exception as e:
            print(f'Exception occurred: {e}')
            return []

    async def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()  # Only need to search once since using API.
