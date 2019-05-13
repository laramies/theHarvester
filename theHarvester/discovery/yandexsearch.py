from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import re
import requests
import time


class search_yandex:

    def __init__(self, word, limit, start):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = 'yandex.com'
        self.hostname = 'yandex.com'
        self.limit = limit
        self.counter = start

    def do_search(self):
        url = 'http://' + self.server + '/search?text=%40' + self.word + '&numdoc=50&lr=' + str(self.counter)
        headers = {
            'Host': self.hostname,
            'User-agent': Core.get_user_agent()
        }
        h = requests.get(url=url, headers=headers)
        self.results = h.text
        self.totalresults += self.results
        print(self.results)

    def do_search_files(self, files):  # TODO
        url = 'http://' + self.server + '/search?text=%40' + self.word + '&numdoc=50&lr=' + str(self.counter)
        headers = {
            'Host': self.hostname,
            'User-agent': Core.get_user_agent()
        }
        h = requests.get(url=url, headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def check_next(self):
        renext = re.compile('topNextUrl')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = '1'
            print(str(self.counter))
        else:
            nexty = '0'
        return nexty

    def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_files(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.fileurls(self.files)  # self.files is not init?

    def process(self):
        while self.counter <= self.limit:
            self.do_search()
            self.counter += 50
            print(f'Searching  {self.counter} results.')

    def process_files(self, files):
        while self.counter < self.limit:
            self.do_search_files(files)
            time.sleep(getDelay())
            self.counter += 50
