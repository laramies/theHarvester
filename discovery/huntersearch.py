from parsers import myparser
import requests
from discovery.constants import *


class search_hunter:

    def __init__(self, word, limit, start):
        self.word = word
        self.limit = 100
        self.start = start
        self.key = hunterAPI_key
        if self.key == "":
            raise MissingKey(True)
        self.results = ""
        self.totalresults = ""
        self.counter = start
        self.database = "https://api.hunter.io/v2/domain-search?domain=" + word + "&api_key=" + self.key +"&limit=" + str(self.limit)

    def do_search(self):
        try:
            r = requests.get(self.database)
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results

    def process(self):
            self.do_search()  # only need to do it once
            print('\tDone Searching Results')

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_profiles(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.profiles()
