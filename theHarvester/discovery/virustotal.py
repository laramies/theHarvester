from theHarvester.lib.core import Core
from theHarvester.parsers import myparser
import requests


class SearchVirustotal:

    def __init__(self, word):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.quantity = '100'
        self.counter = 0

    def do_search(self):
        base_url = f'https://www.virustotal.com/ui/domains/{self.word}/subdomains?relationships=resolutions&cursor=STMwCi4%3D&limit=40'
        headers = {'User-Agent': Core.get_user_agent()}
        res = requests.get(base_url, headers=headers)
        self.results = res.content.decode('UTF-8')
        self.totalresults += self.results

    def get_hostnames(self):
        rawres = myparser.Parser(self.results, self.word)
        return rawres.hostnames()

    def process(self):
        print('\tSearching results.')
        self.do_search()
        self.get_hostnames()
