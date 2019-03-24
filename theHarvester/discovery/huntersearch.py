from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests


class SearchHunter:

    def __init__(self, word, limit, start):
        self.word = word
        self.limit = 100
        self.start = start
        self.key = Core.hunter_key()
        if self.key is None:
            raise MissingKey(True)
        self.results = ""
        self.totalresults = ""
        self.counter = start
        self.database = "https://api.hunter.io/v2/domain-search?domain=" + word + "&api_key=" + self.key + "&limit=" + str(self.limit)

    def do_search(self):
        try:
            r = requests.get(self.database)
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results

    def process(self):
            self.do_search()  # Only need to do it once.

    def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_profiles(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.profiles()
