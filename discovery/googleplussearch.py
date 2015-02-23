import string
import requests
import sys
import myparser
import re


class search_googleplus:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.google.com"
        self.hostname = "www.google.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        try:
            urly="https://" + self.server + "/search?num=100&start=" + str(self.counter) + "&hl=en&meta=&q=site%3Aplus.google.com%20intext%3A%22Works%20at%22%20" + self.word+ "%20-inurl%3Aphotos%20-inurl%3Aabout%20-inurl%3Aposts%20-inurl%3Aplusones"
        except Exception, e:
            print e
        try:
            headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:34.0) Gecko/20100101 Firefox/34.0'}
            r=requests.get(urly,headers=headers)
        except Exception,e:
            print e
        self.results = r.content 
        self.totalresults += self.results

    def get_people(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.people_googleplus()

    def process(self):
        while (self.counter < self.limit):
            self.do_search()
            self.counter += 100
            print "\tSearching " + str(self.counter) + " results.."
