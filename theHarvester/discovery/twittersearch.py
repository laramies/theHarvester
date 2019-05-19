from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests
import time
import re


class search_twitter:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.hostname = 'www.google.com'
        self.quantity = '100'
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        try:
            urly = 'https://' + self.server + '/search?num=100&start=' + str(self.counter) + '&hl=en&meta=&q=site%3Atwitter.com%20intitle%3A%22on+Twitter%22%20' + self.word
        except Exception as e:
            print(e)
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            r = requests.get(urly, headers=headers)
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results

    def get_people(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        to_parse = rawres.people_twitter()
        # fix invalid handles that look like @user other_output
        handles = set()
        for handle in to_parse:
            result = re.search(r'^@?(\w){1,15}', handle)
            if result:
                handles.add(result.group(0))
        return handles

    def process(self):
        while self.counter < self.limit:
            self.do_search()
            time.sleep(getDelay())
            self.counter += 100
            print(f'\tSearching {self.counter} results.')
