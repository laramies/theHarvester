from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests
import time


class SearchLinkedin:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.quantity = '100'
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        urly = 'http://' + self.server + '/search?num=100&start=' + str(self.counter) + '&hl=en&meta=&q=site%3Alinkedin.com/in%20' + self.word
        try:
            headers = {'User-Agent': Core.get_user_agent()}
            r = requests.get(urly, headers=headers)
            self.results = r.text
            if search(self.results):
                try:
                    self.results = google_workaround(urly)
                    if isinstance(self.results, bool):
                        print('Google is blocking your ip and the workaround, returning')
                        return
                except Exception:
                    # google blocked, no useful result
                    return
        except Exception as e:
            print(e)
        time.sleep(getDelay())
        self.totalresults += self.results

    def get_people(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.people_linkedin()

    def get_links(self):
        links = myparser.Parser(self.totalresults, self.word)
        return splitter(links.links_linkedin())

    def process(self):
        while self.counter < self.limit:
            self.do_search()
            time.sleep(getDelay())
            self.counter += 100
            print(f'\tSearching {self.counter} results.')
