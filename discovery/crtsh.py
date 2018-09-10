import string
import requests
import sys
import myparser
import re

TIMEOUT=30

class search_crtsh:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.google.com"
        self.hostname = "www.google.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100116 Firefox/3.7"
        self.quantity = "100"
        self.counter = 0
        

    def do_search(self):
        headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:34.0) Gecko/20100101 Firefox/34.0'}
        url = "https://crt.sh/?q=%25{}".format(self.word)
        r=requests.get(url,headers=headers, timeout=TIMEOUT)
        self.results = r.text
        self.totalresults += self.results

    def get_hostnames(self):
        rawres = myparser.parser(self.results, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()
        print("\tSearching CRT.sh results..")