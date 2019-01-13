from discovery.constants import *
from lib.core import *
from parsers import myparser
import re
import requests
import time


class SearchAsk:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.ask.com'
        self.hostname = 'www.ask.com'
        self.quantity = '100'
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        headers = {
            'User-agent': Core.get_user_agent()
        }
        url = 'https://' + self.server + '/web?q=%40' + self.word + '&pu=100&page=' + str(self.counter)
        h = requests.get(url=url, headers=headers)
        time.sleep(getDelay())
        self.results = h.text
        self.totalresults += self.results

    def check_next(self):
        renext = re.compile('>  Next  <')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = '1'
        else:
            nexty = '0'
        return nexty

    def get_people(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.people_jigsaw()

    def process(self):
        while self.counter < self.limit:
            self.do_search()
            more = self.check_next()
            if more == '1':
                self.counter += 100
            else:
                break
