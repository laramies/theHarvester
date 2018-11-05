import myparser
import time
import requests

class search_hunter:

    def __init__(self, word, limit, start,key):
        self.word = word
        self.limit = limit
        self.start = start
        self.key = key
        self.results = ""
        self.totalresults = ""
        self.counter = start
        self.database = "https://api.hunter.io/v2/domain-search?domain=" + word + "&api_key=" + key

    def do_search(self):
        try:
            r = requests.get(self.database)
        except Exception,e:
            print e
        self.results = r.content
        self.totalresults += self.results

    def process(self):
            self.do_search() #only need to do it once
            print '\tDone Searching Results'

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_profiles(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.profiles()
