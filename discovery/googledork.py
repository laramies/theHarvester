import string
import sys
import myparser
import re
import time
import requests

class google_dork:

    def __init__(self, target, limit, start):
        self.target = target
        self.results = ""
        self.totalresults = ""
        self.dorks = []
        self.links = []
        self.database = "https://www.google.com/search?q="
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = limit
        self.counter = start

    def append_dorks(self):
        try: #wrap in try-except incase filepaths are messed up
            with open('../theHarvester/wordlists/dorks.txt',mode='r') as fp:
                for dork in fp:
                    self.dorks.append(dork)
        except IOError as error:
            print(error)

    def construct_dorks(self):
        #format is: site:targetwebsite.com + space + inurl:admindork
        colon = "%3A"
        plus = "%2B"
        space = '+'
        #populate links list
        self.links = [self.database + space + str(dork).replace(':',colon).replace('+',plus) for dork in self.dorks]

    def temp(self):
        for link in self.links:
            print('link is: link')

    def do_search(self):
        for link in self.links:
              try:
                  req = requests.get(link)
                  time.sleep(0.2)
                  self.results = req.content
                  self.totalresults += self.results
              except Exception: #if something happens
                  continue

    def get_emails(self):
        pass

    def get_files(self):
        pass
