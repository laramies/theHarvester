from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import grequests


class SearchVirustotal:

    def __init__(self, word):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.quantity = '100'
        self.counter = 0

    def do_search(self):
        base_url = f'https://www.virustotal.com/domain/{self.word}/details'
        headers = {'User-Agent': Core.get_user_agent()}
        request = grequests.get(base_url, headers=headers)
        res = grequests.map(request)
        self.results = res.content.decode('UTF-8')
        self.totalresults += self.results


    def get_hostnames(self):
        rawres = myparser.Parser(self.results, self.word)
        return rawres.hostnames()

    def process(self):
        print('\tSearching results.')
