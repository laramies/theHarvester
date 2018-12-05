import string
import sys
import re
import time
import requests
import json

class search_googlecertificates:
    # https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain=
    def __init__(self, word, limit, start):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = "www.google.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = limit
        self.counter = start

    def do_search(self):
        try:
            urly="https://" + self.server + "/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain=" + self.word
        except Exception as e:
            print (e)
        try:
            r=requests.get(urly)
        except Exception as e:
            print (e)
        self.results = r.text
        self.totalresults += self.results

    def get_domains(self):
	    domains = []
	    rawres = json.loads(self.totalresults.split("\n", 2)[2])
	    for array in rawres[0][1]:
	    	domains.append(array[1])
	    return list(set(domains))

    def process(self):
        self.do_search()
