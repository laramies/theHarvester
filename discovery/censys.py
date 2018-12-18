import requests
import censysparser
import time
from discovery.constants import *

class search_censys:

    def __init__(self, word):
        self.word = word
        self.url = ""
        self.page = ""
        self.results = ""
        self.total_results = ""
        self.server = "censys.io"

    def do_search(self):
        try:
            headers = {'user-agent': getUserAgent(), 'Accept': '*/*', 'Referer': self.url}
            response = requests.get(self.url, headers=headers)
            self.results = response.text
            self.total_results += self.results
        except Exception as e:
            print(e)

    def process(self):
        self.url = "https://" + self.server + "/ipv4/_search?q=" + str(self.word) + "&page=1"
        self.do_search()
        self.counter = 2
        pages = censysparser.parser(self)
        totalpages = pages.search_numberofpages()
        while self.counter <= totalpages:
            try:
                self.page = str(self.counter)
                self.url = "https://" + self.server + "/ipv4/_search?q=" + str(self.word) + "&page=" + str(self.page)
                print("\t - Searching Censys results page " + self.page + "...")
                self.do_search()
                time.sleep(getDelay())
            except Exception as e:
                print("Error occurred: " + str(e))
            self.counter += 1

    def get_hostnames(self):
        try:
            hostnames = censysparser.parser(self)
            return hostnames.search_hostnames()
        except Exception as e:
            print("Error occurred: " + str(e))

    def get_ipaddresses(self):
        try:
            ips = censysparser.parser(self)
            return ips.search_ipaddresses()
        except Exception as e:
            print("Error occurred: " + str(e))
