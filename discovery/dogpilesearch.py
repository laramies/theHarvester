import myparser
import time
import requests
from discovery.constants import *

class search_dogpile:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = "www.dogpile.com"
        self.hostname = "www.dogpile.com"
        self.limit = limit
        self.counter = 0

    def do_search(self):
        # Dogpile is hardcoded to return 10 results
        url = 'http://' + self.server + "/search/web?qsi=" + str(self.counter) \
              + "&q=\"%40" + self.word + "\""
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
