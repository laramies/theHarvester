# HTTPS DuckDuckGo search for theHarvester
# By Gilberto Najera-Gutierrez (gilnajera@gmail.com)


import myparser
import re
import time
import requests


class search_duckduck:
    def __init__(self, word, limit, start):
        self.word = word
        self.files = "pdf"
        self.results = ""
        self.totalresults = ""
        self.server = "duckduckgo.com"
        self.server_api = ""
        self.hostname = "duckduckgo.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = limit
        self.counter = start
        self.api_key = ""

    def do_search(self):
        r = requests.get('https://' + self.hostname + '/?q=\"' + self.word + '\"')
        returncode = r.status_code
        headers = r.headers
        self.results = r.text
        self.totalresults += self.results

    def do_search_files(self, files):
        r = requests.get("https://" + self.hostname + "/?q=filetype:" + files + "%20site:" + self.word)
        returncode = r.status_code
        headers = r.headers
        self.results = r.text

    def do_search_profiles(self):
        r = requests.get(
            "https://" + self.hostname + '/?q=site:www.google.com%20intitle:"Google%20Profile"%20"Companies%20I%27ve%20worked%20for"%20"at%20' + self.word)
        returncode = r.status_code
        headers = r.headers
        self.results = r.text
        self.totalresults += self.results

    def check_next(self):
        renext = re.compile('>  Next  <')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = "1"
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

    def get_profiles(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.profiles()

    def process(self):
        print "[+] TheHarvester DuckDuckGo search"
        print "[+] Coded by Gilberto Najera gilnajera@gmail.com"
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            # more = self.check_next()
            time.sleep(1)
            print "\tSearching " + str(self.counter) + " results..."
            self.counter += 100

    def process_files(self, files):
        print "process_files"
        while self.counter <= self.limit:
            self.do_search_files(files)
            time.sleep(1)
            self.counter += 100
            print "\tSearching " + str(self.counter) + " results..."

    def process_profiles(self):
        print "process_profiles"
        while self.counter < self.limit:
            self.do_search_profiles()
            time.sleep(0.3)
            self.counter += 100
            print "\tSearching " + str(self.counter) + " results..."
