from theHarvester.discovery.constants import *
from theHarvester.parsers import myparser
import grequests
import requests
import random
import time


class SearchTrello:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.quantity = '100'
        self.limit = 300
        self.trello_urls = []
        self.hostnames = []
        self.counter = 0

    def do_search(self):
        base_url = f'https://{self.server}/search?num=300&start=xx&hl=en&q=site%3Atrello.com%20{self.word}'
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 20) if num <= self.limit]
        # limit is 20 as that is the most results google will show per num
        headers = {'User-Agent': googleUA}
        for url in urls:
            try:
                resp = requests.get(url, headers=headers)
                self.results = resp.text
                if search(self.results):
                    try:
                        self.results = google_workaround(base_url)
                        if isinstance(self.results, bool):
                            print('Google is blocking your ip and the workaround, returning')
                            return
                    except Exception as e:
                        print(e)
                self.totalresults += self.results
                time.sleep(getDelay() - .5)
            except Exception as e:
                print(f'An exception has occurred in trello: {e}')

    def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.emails()

    def get_urls(self):
        try:
            rawres = myparser.Parser(self.totalresults, 'trello.com')
            self.trello_urls = set(rawres.urls())
            self.totalresults = ''
            # reset what totalresults as before it was just google results now it is trello results
            headers = {'User-Agent': random.choice(['curl/7.37.0', 'Wget/1.19.4'])}
            # do not change the headers
            req = (grequests.get(url, headers=headers, timeout=4) for url in self.trello_urls)
            responses = grequests.imap(req, size=8)
            for response in responses:
                self.totalresults += response.content.decode('UTF-8')

            rawres = myparser.Parser(self.totalresults, self.word)
            self.hostnames = rawres.hostnames()
        except Exception as e:
            print(f'Error occurred: {e}')

    def process(self):
        self.do_search()
        self.get_urls()
        print(f'\tSearching {self.counter} results.')

    def get_results(self) -> tuple:
        return self.get_emails(), self.hostnames, self.trello_urls
