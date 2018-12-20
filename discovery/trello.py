import requests
import myparser
import censysparser
from discovery.constants import *
import time

class search_trello:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.google.com"
        self.hostname = "www.google.com"
        self.quantity = "100"
        self.limit = limit
        self.counter = 0

    def do_search(self):
        try:
            urly="https://"+ self.server + "/search?num=100&start=" + str(self.counter) + "&hl=en&meta=&q=site%3Atrello.com%20" + self.word
        except Exception as e:
            print(e)
        headers = {'User-Agent': getUserAgent()}
        try:
            r=requests.get(urly,headers=headers)
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_urls(self):
        try:
            urls = myparser.parser(self.totalresults,"trello.com")
            return urls.urls()
        except Exception as e:
            print("Error occurred: " + str(e))

    def process(self):
        while (self.counter < self.limit):
            self.do_search()
            time.sleep(getDelay())
            self.counter += 100
            print("\tSearching " + str(self.counter) + " results..")
