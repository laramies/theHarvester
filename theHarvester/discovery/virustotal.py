from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests


class SearchVirustotal:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.hostname = 'www.google.com'
        self.quantity = '100'
        self.counter = 0

    def do_search(self):
        try:
            urly = 'https://www.virustotal.com/en/domain/' + self.word + '/information/'
        except Exception as e:
            print(e)
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            r = requests.get(urly, headers=headers)
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results

    def get_hostnames(self):
        rawres = myparser.Parser(self.results, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()
        print('\tSearching results.')
