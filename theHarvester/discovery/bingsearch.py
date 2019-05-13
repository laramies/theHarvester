from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests
import time


class SearchBing:

    def __init__(self, word, limit, start):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.bing.com'
        self.apiserver = 'api.search.live.net'
        self.hostname = 'www.bing.com'
        self.quantity = '50'
        self.limit = int(limit)
        self.bingApi = Core.bing_key()
        self.counter = start

    def do_search(self):
        headers = {
            'Host': self.hostname,
            'Cookie': 'SRCHHPGUSR=ADLT=DEMOTE&NRSLT=50',
            'Accept-Language': 'en-us,en',
            'User-agent': Core.get_user_agent()
        }
        h = requests.get(url=('https://' + self.server + '/search?q=%40"' + self.word + '"&count=50&first=' + str(self.counter)), headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def do_search_api(self):
        url = 'https://api.cognitive.microsoft.com/bing/v7.0/search?'
        params = {
            'q': self.word,
            'count': str(self.limit),
            'offset': '0',
            'mkt': 'en-us',
            'safesearch': 'Off'
        }
        headers = {'User-Agent': Core.get_user_agent(), 'Ocp-Apim-Subscription-Key': self.bingApi}
        h = requests.get(url=url, headers=headers, params=params)
        self.results = h.text
        self.totalresults += self.results

    def do_search_vhost(self):
        headers = {
            'Host': self.hostname,
            'Cookie': 'mkt=en-US;ui=en-US;SRCHHPGUSR=NEWWND=0&ADLT=DEMOTE&NRSLT=50',
            'Accept-Language': 'en-us,en',
            'User-agent': Core.get_user_agent()
        }
        url = 'http://' + self.server + '/search?q=ip:' + self.word + '&go=&count=50&FORM=QBHL&qs=n&first=' + str(self.counter)
        h = requests.get(url=url, headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_allhostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames_all()

    def process(self, api):
        if api == 'yes':
            if self.bingApi is None:
                raise MissingKey(True)
        while self.counter < self.limit:
            if api == 'yes':
                self.do_search_api()
                time.sleep(getDelay())
            else:
                self.do_search()
                time.sleep(getDelay())
            self.counter += 50
            print(f'\tSearching {self.counter} results.')

    def process_vhost(self):
        # Maybe it is good to use other limit for this.
        while self.counter < self.limit:
            self.do_search_vhost()
            self.counter += 50
