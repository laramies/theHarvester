from lib.core import *
from parsers import myparser
import requests


class SearchPgp:

    def __init__(self, word):
        self.word = word
        self.results = ""
        self.server = 'pgp.mit.edu'
        self.hostname = 'pgp.mit.edu'

    def process(self):
        print('\tSearching results.')
        try:
            url = 'http://' + self.server + '/pks/lookup?search=' + self.word + '&op=index'
            headers = {
                'Host': self.hostname,
                'User-agent': Core.get_user_agent()
            }
            h = requests.get(url=url, headers=headers)
            self.results = h.text
            self.results += self.results
        except Exception as e:
            print('Unable to connect to PGP server: ', str(e))

    def get_emails(self):
        rawres = myparser.Parser(self.results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.results, self.word)
        return rawres.hostnames()
