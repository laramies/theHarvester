from lib.core import *
from parsers import myparser
import requests


class SearchNetcraft:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.hostname = 'www.google.com'
        self.quantity = '100'
        self.counter = 0

    def do_search(self):
        urly = 'https://searchdns.netcraft.com/?host=' + self.word + '&x=0&y=0'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            request = requests.get(urly, headers=headers)
        except Exception as e:
            print(e)
        self.results = request.text
        self.totalresults += self.results

    def get_hostnames(self):
        rawres = myparser.Parser(self.results, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()
        print('\tSearching results.')
