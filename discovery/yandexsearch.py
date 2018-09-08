import string
import sys
import myparser
import re
import time
import requests

class search_yandex:

    def __init__(self, word, limit, start):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = "yandex.com"
        self.hostname = "yandex.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.limit = limit
        self.counter = start

    def do_search(self):
        headers = { 'User-agent' : self.userAgent }
        h = requests.get("http://{}/search?text=%40{}&numdoc=50&lr={}".format(self.server, self.word, self.counter), headers=headers)
        self.results = h.text 
        self.totalresults += self.results
        print(self.results)

    def do_search_files(self, files):  # TODO
        headers = { 'User-agent' : self.userAgent }
        h = requests.get("http://{}/search?text=%40{}&numdoc=50&lr={}".format(self.server, self.word, self.counter), headers=headers)
        self.results = h.text 
        self.totalresults += self.results

    def check_next(self):
        renext = re.compile('topNextUrl')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = "1"
            print(str(self.counter))
        else:
            nexty = "0"
        return nexty

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_files(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.fileurls(self.files)

    def process(self):
        while self.counter <= self.limit:
            self.do_search()
            self.counter += 50
            print("Searching " + str(self.counter) + " results...")

    def process_files(self, files):
        while self.counter < self.limit:
            self.do_search_files(files)
            time.sleep(0.3)
            self.counter += 50
