import httplib
import sys
import random
import requests
import censysparser

class search_censys:

    def __init__(self, word):
        self.word = word
        self.url = ""
        self.page = ""
        self.results = ""
        self.total_results = ""
        self.server = "censys.io"
        self.userAgent = ["(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
          ,("Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) " +
          "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36"),
          ("Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) " +
          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254"),
          "Mozilla/5.0 (SMART-TV; X11; Linux armv7l) AppleWebKit/537.42 (KHTML, like Gecko) Chromium/25.0.1349.2 Chrome/25.0.1349.2 Safari/537.42"
          ,"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991"
          ,"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52"
          ,"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
          ,"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
          ,"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"]
        
    def do_search(self):
        try:
            headers = {'user-agent': random.choice(self.userAgent),'Accept':'*/*','Referer':self.url}
            response = requests.get(self.url, headers=headers)
            self.results = response.content
            self.total_results += self.results
        except Exception,e:
            print e

    def process(self,morepage=None):
        try:
            if (morepage is not None):
                self.page =str(morepage) 
                baseurl = self.url
                self.url = baseurl + "&page=" + self.page
            else:
                self.url="https://" + self.server + "/ipv4/_search?q=" + self.word
            self.do_search()
            print "\tSearching Censys results.."
        except Exception,e:
            print("Error occurred: " + e)

    def get_hostnames(self):
        try:
            hostnames = censysparser.parser(self)
            return hostnames.search_hostnames()
        except Exception,e:
            print("Error occurred: " + e)   

    def get_ipaddresses(self):
        try:
            ips = censysparser.parser(self)
            return ips.search_ipaddresses()
        except Exception,e:
            print("Error occurred: " + e) 
    
    def get_totalnumberofpages(self):
        try:
            pages = censysparser.parser(self)
            return pages.search_numberofpages()
        except Exception,e:
            print("Error occurred: " + e) 

