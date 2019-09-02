from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import grequests


class SearchThreatcrowd:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""

    def do_search(self):
        base_url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.word}'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            request = grequests.get(base_url, headers=headers)
            data = grequests.map([request])
            self.results = data[0].content.decode('UTF-8')
        except Exception as e:
            print(e)
        self.totalresults += self.results

    def get_hostnames(self):
        return myparser.Parser(self.results, self.word).hostnames()

    def process(self):
        self.do_search()
        self.get_hostnames()
        print('\tSearching results.')
