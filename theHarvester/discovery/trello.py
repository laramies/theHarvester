from theHarvester.discovery.constants import *
from theHarvester.parsers import myparser
import requests
import time


class search_trello:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.hostname = 'www.google.com'
        self.quantity = '100'
        self.limit = limit
        self.counter = 0

    def do_search(self):
        try:
            urly = 'https://' + self.server + '/search?num=100&start=' + str(
                self.counter) + '&hl=en&q=site%3Atrello.com%20' + self.word
        except Exception as e:
            print(e)
        headers = {'User-Agent': googleUA}
        try:
            r = requests.get(urly, headers=headers)
            time.sleep(getDelay())
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results

    def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.emails()

    def get_urls(self):
        try:
            rawres = myparser.Parser(self.totalresults, 'trello.com')
            trello_urls = rawres.urls()
            visited = set()
            for url in trello_urls:
                # Iterate through Trello URLs gathered and visit them, append text to totalresults.
                if url not in visited:  # Make sure visiting unique URLs.
                    visited.add(url)
                    self.totalresults += requests.get(url=url, headers={'User-Agent': googleUA}).text
            rawres = myparser.Parser(self.totalresults, self.word)
            return rawres.hostnames(), trello_urls
        except Exception as e:
            print(f'Error occurred: {e}')

    def process(self):
        while self.counter < self.limit:
            self.do_search()
            if search(self.results):
                time.sleep(getDelay() * 5)
            else:
                time.sleep(getDelay())
            self.counter += 100
            print(f'\tSearching {self.counter} results.')
