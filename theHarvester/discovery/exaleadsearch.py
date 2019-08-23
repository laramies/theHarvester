from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import re
import time
import grequests
import requests


class SearchExalead:

    def __init__(self, word, limit, start):
        self.word = word
        self.files = 'pdf'
        self.results = ""
        self.total_results = ""
        self.server = 'www.exalead.com'
        self.hostname = 'www.exalead.com'
        self.limit = limit
        self.counter = start

    def do_search(self):
        base_url = f'https://{self.server}/search/web/results/?q=%40{self.word}&elements_per_page=50&start_index=xx'
        headers = {
            'Host': self.hostname,
            'Referer': ('http://' + self.hostname + '/search/web/results/?q=%40' + self.word),
            'User-agent': Core.get_user_agent()
        }
        urls = [base_url.replace("xx", str(num)) for num in range(self.counter, self.limit, 50) if num <= self.limit]
        req = []
        for url in urls:
            req.append(grequests.get(url, headers=headers, timeout=5))
            time.sleep(3)
        responses = grequests.imap(tuple(req), size=3)
        for response in responses:
            # TODO if decoded content contains information about solving captcha print message to user to visit website
            # TODO to solve it or use a vpn as it appears to be ip based
            self.total_results += response.content.decode('UTF-8')

    def do_search_files(self, files):
        url = f'https://{self.server}/search/web/results/?q=%40{self.word}filetype:{self.files}&elements_per_page' \
            f'=50&start_index={self.counter} '
        headers = {
            'Host': self.hostname,
            'Referer': ('http://' + self.hostname + '/search/web/results/?q=%40' + self.word),
            'User-agent': Core.get_user_agent()
        }
        h = requests.get(url=url, headers=headers)
        self.results = h.text
        self.total_results += self.results

    def check_next(self):
        renext = re.compile('topNextUrl')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = '1'
            print(str(self.counter))
        else:
            nexty = '0'
        return nexty

    def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.hostnames()

    def get_files(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.fileurls(self.files)

    def process(self):
        print('Searching results')
        self.do_search()

    def process_files(self, files):
        while self.counter < self.limit:
            self.do_search_files(files)
            time.sleep(getDelay())
            more = self.check_next()
            if more == '1':
                self.counter += 50
            else:
                break
