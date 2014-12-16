import string
import httplib
import sys
import myparser
import re


class search_ask:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.ask.com"
        self.hostname = "www.ask.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        h = httplib.HTTP(self.server)
        h.putrequest(
            'GET',
            "/web?q=%40" +
            self.word +
            "&pu=100&page=" +
            self.counter)
        h.putheader('User-agent', self.userAgent)
        h.endheaders()
        returncode, returnmsg, headers = h.getreply()
        self.results = h.getfile().read()
        self.totalresults += self.results

    def check_next(self):
        renext = re.compile('>  Next  <')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = "1"
        else:
            nexty = "0"
        return nexty

    def get_people(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.people_jigsaw()

    def process(self):
        while (self.counter < self.limit):
            self.do_search()
            more = self.check_next()
            if more == "1":
                self.counter += 100
            else:
                break
