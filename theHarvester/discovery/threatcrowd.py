from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests


class SearchThreatcrowd:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.hostname = 'www.google.com'
        self.quantity = '100'
        self.counter = 0

    def do_search(self):
        url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.word}'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            request = requests.get(url, headers=headers)
            self.results = request.text
        except Exception as e:
            print(e)
        self.totalresults += self.results

    def get_hostnames(self):
        return myparser.Parser(self.results, self.word).hostnames()

    def process(self):
        self.do_search()
        print('\tSearching results.')
