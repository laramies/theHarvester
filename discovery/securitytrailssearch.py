import myparser
import requests
import sys

class search_hunter:

    def __init__(self, word, limit, start):
        self.word = word
        self.limit = 100
        self.start = start
        self.key = ""
        if self.key == "":
            print("You need an API key in order to use the SecurityTrails search engine. You can get one here: https://securitytrails.com/")
            sys.exit()
        self.results = ""
        self.totalresults = ""
        self.counter = start
        self.database = "https://api.securitytrails.com/v1/"

    def authenticate(self):
        #method to authenticate api key before sending requests
        headers = {'APIKEY': self.key}
        url = self.database + 'ping'
        requests.get(url,headers=headers)


    def do_search(self):
        try:
            r = requests.get(self.database)
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results

    def process(self):
            self.do_search()
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
