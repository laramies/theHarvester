import requests
import cymonparser
from discovery.constants import *
import time

class search_cymon:

    def __init__(self, word):
        self.word = word
        self.url = ""
        self.results = ""
        self.server = "cymon.io"

    def do_search(self):
        try:
            headers = {'user-agent':getUserAgent() ,'Accept':'*/*','Referer':self.url}
            response = requests.get(self.url, headers=headers)
            time.sleep(getDelay())
            self.results = response.content
        except Exception as e:
            print(e)

    def process(self):
        try:
            self.url="https://" + self.server + "/domain/" + str(self.word)
            print("\tSearching Cymon results...")
            self.do_search()
        except Exception as e:
            print("Error occurred: " + str(e))

    def get_ipaddresses(self):
        try:
            ips = cymonparser.parser(self)
            return ips.search_ipaddresses()
        except Exception as e:
            print("Error occurred: " + str(e))
