import myparser
import requests
from discovery.constants import *

class search_google_labs:

    def __init__(self, list):
        self.results = ""
        self.totalresults = ""
        self.server = "labs.google.com"
        self.hostname = "labs.google.com"
        id = 0
        self.set = ""
        for x in list:
            id += 1
            if id == 1:
                self.set = self.set + "q" + str(id) + "=" + str(x)
            else:
                self.set = self.set + "&q" + str(id) + "=" + str(x)

    def do_search(self):
        url = 'http://' + self.server + "/sets?hl-en&" + self.set
        headers = {
            'Host': self.server,
            'User-agent': getUserAgent()
        }
        h = requests.get(url=url, headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def get_set(self):
        rawres = myparser.parser(self.totalresults, list)
        return rawres.set()

    def process(self):
        self.do_search()
