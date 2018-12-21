import myparser
import requests
import sys
import time

class search_securitytrail:

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
        requests.get(url, headers=headers)
        time.sleep(2)

    def do_search(self):
        url = ''
        try:
            #https://api.securitytrails.com/v1/domain/oracle.com?apikey=your_api_key
            url = self.database + 'domain/' + self.word
            headers = {'APIKEY': self.key}
            r = requests.get(url, headers=headers)
            time.sleep(2)
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results
        url += '/subdomains'
        headers = {'APIKEY': self.key}
        r = requests.get(url, headers=headers)
        time.sleep(2)
        self.results = r.text
        self.totalresults += self.results

    def process(self):
        self.authenticate()
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
