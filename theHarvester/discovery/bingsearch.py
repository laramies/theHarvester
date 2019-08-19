from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import grequests


class SearchBing:

    def __init__(self, word, limit, start):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.total_results = ""
        self.server = 'www.bing.com'
        self.apiserver = 'api.search.live.net'
        self.hostname = 'www.bing.com'
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
        base_url = f'https://{self.server}/search?q=%40"{self.word}"&count=50&first=xx'
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 50) if num <= self.limit]
        req = (grequests.get(url, headers=headers, timeout=5) for url in urls)
        responses = grequests.imap(req, size=5)
        for response in responses:
            self.total_results += response.content.decode('UTF-8')

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
        grequests_resp = grequests.get(url=url, headers=headers, params=params)
        response = grequests.map([grequests_resp])
        self.results = response[0].content.decode('UTF-8')
        self.total_results += self.results

    def do_search_vhost(self):
        headers = {
            'Host': self.hostname,
            'Cookie': 'mkt=en-US;ui=en-US;SRCHHPGUSR=NEWWND=0&ADLT=DEMOTE&NRSLT=50',
            'Accept-Language': 'en-us,en',
            'User-agent': Core.get_user_agent()
        }
        base_url = f'http://{self.server}/search?q=ip:{self.word}&go=&count=50&FORM=QBHL&qs=n&first=xx'
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 50) if num <= self.limit]
        req = (grequests.get(url, headers=headers, timeout=5) for url in urls)
        responses = grequests.imap(req, size=5)
        for response in responses:
            self.total_results += response.content.decode('UTF-8')

    def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.hostnames()

    def get_allhostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.hostnames_all()

    def process(self, api):
        if api == 'yes':
            if self.bingApi is None:
                raise MissingKey(True)
        else:
            if api == 'yes':
                self.do_search_api()
            else:
                self.do_search()
            print(f'\tSearching {self.counter} results.')

    def process_vhost(self):
        self.do_search_vhost()
