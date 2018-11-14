import myparser
import time
import requests
import sys

class search_hunter:

    def __init__(self, word, limit, start):
        self.word = word
        self.limit = 100
        self.start = start
        self.key = ""
        if self.key == "":
            print "You need an API key in order to use the Hunter search engine. You can get one here: https://hunter.io"
            sys.exit()
        self.results = ""
        self.totalresults = ""
        self.counter = start
        self.database = "https://api.hunter.io/v2/domain-search?domain=" + word + "&api_key=" + self.key +"&limit=" + str(self.limit)

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
