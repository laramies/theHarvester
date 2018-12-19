import myparser
import requests
from discovery.constants import *

class search_pgp:

    def __init__(self, word):
        self.word = word
        self.results = ""
        self.server = "pgp.mit.edu"
        #self.server = "pgp.rediris.es"
        self.hostname = "pgp.mit.edu"

    def process(self):
        print("\tSearching PGP results...")
        try:
            url = 'http://' + self.server + "/pks/lookup?search=" + self.word + "&op=index"
            headers = {
                'Host': self.hostname,
                'User-agent': getUserAgent()
            }
            h = requests.get(url=url, headers=headers)
            self.results = h.text
            self.results += self.results
        except Exception as e:
            print("Unable to connect to PGP server: ", str(e))

    def get_emails(self):
        rawres = myparser.parser(self.results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.results, self.word)
        return rawres.hostnames()
