import string
import sys
import myparser
import re
import time
if sys.version_info <= (3,0):
    import httplib
else:
    import http.client as httplib


class search_google_labs:

    def __init__(self, list):
        self.results = ""
        self.totalresults = ""
        self.server = "labs.google.com"
        self.hostname = "labs.google.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        id = 0
        self.set = ""
        for x in list:
            id += 1
            if id == 1:
                self.set = self.set + "q" + str(id) + "=" + str(x)
            else:
                self.set = self.set + "&q" + str(id) + "=" + str(x)

    def do_search(self):
        h = requests.get("http://"+self.server+ "/sets?hl=en&" + self.set, headers={'User-agent': self.userAgent})
        self.results = h.text
        self.totalresults += self.results

    def get_set(self):
        rawres = myparser.parser(self.totalresults, list)
        return rawres.set()

    def process(self):
        self.do_search()
