import string
import sys
import myparser
import requests

class search_pgp:

    def __init__(self, word):
        self.word = word
        self.results = ""
        self.server = "pgp.mit.edu"
        #self.server = "pgp.rediris.es"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        
    def process(self):
        print("\tSearching PGP results...")
        headers = { 
            "User-agent" : self.userAgent,
        }
        h = requests.get("http://"+self.server + "/pks/lookup?search=" + self.word + "&op=index", headers=headers)
        self.results = h.text

    def get_emails(self):
        rawres = myparser.parser(self.results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.results, self.word)
        return rawres.hostnames()
