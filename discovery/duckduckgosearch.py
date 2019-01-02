from parsers import myparser
import time
import requests
import json
from discovery.constants import *


class search_duckduckgo:

    def __init__(self, word, limit):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.dorks = []
        self.links = []
        self.database = "https://duckduckgo.com/?q="
        self.api = "https://api.duckduckgo.com/?q=x&format=json&pretty=1"  # currently using api
        self.quantity = "100"
        self.limit = limit

    def do_search(self):
        try:  # do normal scraping
            url = self.api.replace('x', self.word)
            headers = {'User-Agent': getUserAgent()}
            r = requests.get(url, headers=headers)
        except Exception as e:
            print(e)
        time.sleep(getDelay())
        self.results = r.text
        self.totalresults += self.results
        urls = self.crawl(self.results)
        for url in urls:
            try:
                self.totalresults += requests.get(url, headers={'User-Agent': getUserAgent()}).text
                time.sleep(getDelay())
            except Exception:
                continue

    def crawl(self, text):
        """
        function parses json and returns urls
        :param text: formatted json
        :return: set of urls
        """
        urls = set()
        try:
            load = json.loads(text)
            for key in load.keys():  # iterate through keys of dict
                val = load.get(key)
                if isinstance(val, int) or isinstance(val, dict):
                    continue
                if isinstance(val, list):
                    val = val[0]  # first value should be dict
                    if isinstance(val, dict):  # sanity check
                        for key in val.keys():
                            value = val.get(key)
                            if isinstance(value, str) and value != '' and 'https://' in value or 'http://' in value:
                                urls.add(value)
                if isinstance(val, str) and val != '' and 'https://' in val or 'http://' in val:
                    urls.add(val)
            tmp = set()
            for url in urls:
                if '<' in url and 'href=' in url:  # format is <fref="https://www.website.com"/>
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
            print('Exception occurred: ' + str(e))
            return []

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search() # only need to search once since using API
