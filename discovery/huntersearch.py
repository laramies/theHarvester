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
        print 'conducting search'
        try:
            r = requests.get(self.database)
        except Exception,e:
            print e
        self.results = r.content
        self.totalresults += self.results

    def process(self):
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            time.sleep(1)
            print "\tSearching " + str(self.counter) + " results..."
            self.counter += 100

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_profiles(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.profiles()
