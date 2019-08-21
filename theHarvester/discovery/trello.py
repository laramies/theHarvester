from theHarvester.discovery.constants import *
from theHarvester.parsers import myparser
import grequests


class SearchTrello:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.quantity = '100'
        self.limit = limit
        self.counter = 0

    def do_search(self):
        base_url = f'https://{self.server}/search?num=100&start=xx&hl=en&q=site%3Atrello.com%20{self.word}'
        headers = {'User-Agent': googleUA}
        try:
            urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
            request = (grequests.get(url, headers=headers) for url in urls)
            response = grequests.imap(request, size=5)
            for entry in response:
                self.totalresults += entry.content.decode('UTF-8')
        except Exception as e:
            print(e)

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
                    request = grequests.get(url=url, headers={'User-Agent': googleUA})
                    response = grequests.map([request])
                    self.totalresults = response[0].content.decode('UTF-8')
            rawres = myparser.Parser(self.totalresults, self.word)
            return rawres.hostnames(), trello_urls
        except Exception as e:
            print(f'Error occurred: {e}')

    def process(self):
        self.do_search()
        self.get_urls()
        print(f'\tSearching {self.counter} results.')
