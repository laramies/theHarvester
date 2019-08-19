from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import grequests


class SearchHunter:

    def __init__(self, word, limit, start):
        self.word = word
        self.limit = limit
        self.start = start
        self.key = Core.hunter_key()
        if self.key is None:
            raise MissingKey(True)
        self.total_results = ""
        self.counter = start
        self.database = f'https://api.hunter.io/v2/domain-search?domain={word}&api_key={self.key}&limit={self.limit}'

    def do_search(self):
        request = grequests.get(self.database)
        response = grequests.map([request])
        self.total_results = response[0].content.decode('UTF-8')

    def process(self):
        self.do_search()  # Only need to do it once.

    def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.hostnames()

    def get_profiles(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.profiles()
