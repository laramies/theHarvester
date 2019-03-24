from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import json
import requests
import time


class SearchDuckDuckGo:

    def __init__(self, word, limit):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.dorks = []
        self.links = []
        self.database = 'https://duckduckgo.com/?q='
        self.api = 'https://api.duckduckgo.com/?q=x&format=json&pretty=1'  # Currently using API.
        self.quantity = '100'
        self.limit = limit

    def do_search(self):
        try:  # Do normal scraping.
            url = self.api.replace('x', self.word)
            headers = {'User-Agent': googleUA}
            r = requests.get(url, headers=headers)
        except Exception as e:
            print(e)
        time.sleep(getDelay())
        self.results = r.text
        self.totalresults += self.results
        urls = self.crawl(self.results)
        for url in urls:
            try:
                self.totalresults += requests.get(url, headers={'User-Agent': Core.get_user_agent()}).text
                time.sleep(getDelay())
            except Exception:
                continue

    def crawl(self, text):
        """
        Function parses json and returns URLs.
        :param text: formatted json
        :return: set of URLs
        """
        urls = set()
        try:
            load = json.loads(text)
            for key in load.keys():  # Iterate through keys of dict.
                val = load.get(key)
                if isinstance(val, int) or isinstance(val, dict) or val is None:
                    continue
                if isinstance(val, list):
                    if len(val) == 0:  # Make sure not indexing an empty list.
                        continue
                    val = val[0]  # First value should be dict.
                    if isinstance(val, dict):  # Sanity check.
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
            import traceback as t
            print(t.print_exc())
            return []

    def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()  # Only need to search once since using API.
