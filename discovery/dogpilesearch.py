import myparser
import time
import requests

class search_dogpile:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = "www.dogpile.com"
        self.hostname = "www.dogpile.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.limit = limit
        self.counter = 0

    def do_search(self):
        # Dogpile is hardcoded to return 10 results
        url = 'http://' + self.server + "/search/web?qsi=" + str(self.counter) \
              + "&q=\"%40" + self.word + "\""
        headers = {
            'Host': self.hostname,
            'User-agent': self.userAgent
        }
        h = requests.get(url=url, headers=headers)
        self.total_results += h.text

    def process(self):
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            time.sleep(1)
            print("\tSearching " + str(self.counter) + " results...")
            self.counter += 10

    def get_emails(self):
        rawres = myparser.parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.total_results, self.word)
        return rawres.hostnames()
