import requests
import myparser
import time
from discovery.constants import *

class search_googleplus:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.google.com"
        self.hostname = "www.google.com"
        self.quantity = "100"
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        try:
            urly="https://" + self.server + "/search?num=100&start=" + str(self.counter) + "&hl=en&meta=&q=site%3Aplus.google.com%20intext%3A%22Works%20at%22%20" + self.word+ "%20-inurl%3Aphotos%20-inurl%3Aabout%20-inurl%3Aposts%20-inurl%3Aplusones"
        except Exception as e:
            print(e)
        try:
            headers = {'User-Agent': getUserAgent()}
            r=requests.get(urly,headers=headers)
        except Exception as e:
            print(e)
        self.results = r.text
        self.totalresults += self.results

    def get_people(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.people_googleplus()

    def process(self):
        while (self.counter < self.limit):
            self.do_search()
            time.sleep(getDelay())
            self.counter += 100
            print("\tSearching " + str(self.counter) + " results..")
