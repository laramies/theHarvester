import myparser
import time
import requests
from discovery.constants import *

class search_yahoo:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = "search.yahoo.com"
        self.hostname = "search.yahoo.com"
        self.limit = limit
        self.counter = 0

    def do_search(self):
        url = 'http://' + self.server + "/search?p=\"%40" + self.word \
               + "\"&b=" + str(self.counter) + "&pz=10"
        headers = {
            'Host': self.hostname,
            'User-agent': getUserAgent()
        }
        h = requests.get(url=url, headers=headers)
        self.total_results += h.text

    def process(self):
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            time.sleep(getDelay())
            print("\tSearching " + str(self.counter) + " results...")
            self.counter += 10

    def get_emails(self):
        rawres = myparser.parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.total_results, self.word)
        return rawres.hostnames()
