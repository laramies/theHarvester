from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests
import time


class SearchBaidu:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = 'www.baidu.com'
        self.hostname = 'www.baidu.com'
        self.limit = limit
        self.counter = 0

    def do_search(self):
        url = 'http://' + self.server + '/s?wd=%40' + self.word + '&pn=' + str(self.counter) + '&oq=' + self.word
        url = f'https://{self.server}/s?wd=%40{self.word}&pn{self.counter}&oq={self.word}'
        headers = {
            'Host': self.hostname,
            'User-agent': Core.get_user_agent()
        }
        h = requests.get(url=url, headers=headers)
        time.sleep(getDelay())
        self.total_results += h.text

    def process(self):
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            print(f'\tSearching {self.counter} results.')
            self.counter += 10

    def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.hostnames()
