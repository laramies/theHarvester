from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import grequests
import time


class SearchDogpile:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = 'www.dogpile.com'
        self.hostname = 'www.dogpile.com'
        self.limit = limit

    def do_search(self):
        #import ssl
        #ssl._create_default_https_context = ssl._create_unverified_context
        # Dogpile is hardcoded to return 10 results.
        try:
            headers = {'User-agent': Core.get_user_agent()}
            base_url = f'https://{self.server}/search/web?qsi=xx&q=%40{self.word}'
            urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
            req = (grequests.get(u, headers=headers, verify=False, timeout=5) for u in urls)
            resp = grequests.imap(req, size=5)
            for x in resp:
                self.total_results += x.content.decode('UTF-8')
        except Exception as e:
            print(f'Error Occurred: {e}')

    def process(self):
        self.do_search()

    def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.hostnames()

