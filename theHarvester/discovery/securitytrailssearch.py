from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import securitytrailsparser
import requests
import sys
import time


class search_securitytrail:

    def __init__(self, word):
        self.word = word
        self.key = Core.security_trails_key()
        if self.key is None:
            raise MissingKey(True)
        self.results = ""
        self.totalresults = ""
        self.database = "https://api.securitytrails.com/v1/"
        self.info = ()

    def authenticate(self):
        # Method to authenticate API key before sending requests.
        headers = {'APIKEY': self.key}
        url = self.database + 'ping'
        r = requests.get(url, headers=headers).text
        if 'False' in r or 'Invalid authentication' in r:
            print('\tKey could not be authenticated exiting program.')
            sys.exit(-2)
        time.sleep(2)

    def do_search(self):
        url = ''
        headers = {}
        try:
            # https://api.securitytrails.com/v1/domain/domain.com
            url = self.database + 'domain/' + self.word
            headers = {'APIKEY': self.key}
            r = requests.get(url, headers=headers)
            time.sleep(2)  # Not random delay because 2 seconds is required due to rate limit.
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results
        url += '/subdomains'  # Get subdomains now.
        r = requests.get(url, headers=headers)
        time.sleep(2)
        self.results = r.text
        self.totalresults += self.results

    def process(self):
        self.authenticate()
        self.do_search()
        parser = securitytrailsparser.Parser(word=self.word, text=self.totalresults)
        self.info = parser.parse_text()
        # Create parser and set self.info to tuple returned from parsing text.
        print('\tDone Searching Results')

    def get_ips(self):
        return self.info[0]

    def get_hostnames(self):
        return self.info[1]
