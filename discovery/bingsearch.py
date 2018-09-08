import string
import re
import time
import sys
import requests

class search_bing:

    def __init__(self, word, limit, start):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.bing.com"
        self.apiserver = "api.search.live.net"
        self.hostname = "www.bing.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "50"
        self.limit = int(limit)
        self.bingApi = ""
        self.counter = start

    def do_search(self):

        headers = { 'Cookie' : 'SRCHHPGUSR=ADLT=DEMOTE&NRSLT=50',
                    'Accept-Language' : 'en-us,en',
                    'User-agent' : self.userAgent
                    }
        h = requests.get("http://{}/search?q=%40{}&count=50&first={}".format(self.server, self.word, self.counter), headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def do_search_api(self):
        headers = {'User-agent' : self.userAgent }
        h = requests.get("http://{}/xml.aspx?Appid={}&query=%40{}&sources=web&web.count=40&web.offset={}".format(self.apiserver, self.bingApi, self.word, self.counter), headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def do_search_vhost(self):
        headers = {
                'Accept-Language' : 'en-us,en',
                'Cookie' : 'mkt=en-US;ui=en-US;SRCHHPGUSR=NEWWND=0&ADLT=DEMOTE&NRSLT=50',
                'User-agent' : self.userAgent,
                }
        h = requests.get( "http://{}/search?q=ip:{}&go=&count=50&FORM=QBHL&qs=n&first={}".format(self.server, serlf.word, self.counter), headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_allhostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames_all()

    def process(self, api):
        if api == "yes":
            if self.bingApi == "":
                print("Please insert your API key in the discovery/bingsearch.py")
                sys.exit()
        while (self.counter < self.limit):
            if api == "yes":
                self.do_search_api()
                time.sleep(0.3)
            else:
                self.do_search()
                time.sleep(1)
            self.counter += 50
            print("\tSearching " + str(self.counter) + " results...")

    def process_vhost(self):
        # Maybe it is good to use other limit for this.
        while (self.counter < self.limit):
            self.do_search_vhost()
            self.counter += 50
