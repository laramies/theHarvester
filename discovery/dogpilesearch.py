from discovery.constants import *
from lib.core import *
from parsers import myparser
import requests
import time


class SearchDogpile:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = 'www.dogpile.com'
        self.hostname = 'www.dogpile.com'
        self.limit = limit
        self.counter = 0

    def do_search(self):
        # Dogpile is hardcoded to return 10 results.
        url = 'https://' + self.server + "/search/web?qsi=" + str(self.counter) \
              + "&q=\"%40" + self.word + "\""
        headers = {
            'Host': self.hostname,
            'User-agent': Core.get_user_agent()
        }
        try:
            h = requests.get(url=url, headers=headers)
            self.total_results += h.text
        except requests.exceptions.ConnectionError:
            pass

    def process(self):
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            time.sleep(getDelay())
            print(f'\tSearching {self.counter} results.')
            self.counter += 10

    def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.hostnames()