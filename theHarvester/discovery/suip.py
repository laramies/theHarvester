from theHarvester.lib.core import *
import grequests
from bs4 import BeautifulSoup

class SearchSuip:

    def __init__(self, word):
        self.word = word
        self.results = ''
        self.totalresults = ''
        self.totalhosts = set()
        self.totalips = set()

    def do_search(self):
        base_url = "https://suip.biz/"
        params = (
            ('act', 'subfinder'),
        )

        data = {
            'url': self.word.replace('www.', ''),
            'Submit1': 'Submit'
        }

        headers = {'User-Agent': Core.get_user_agent()}
        try:
            request = grequests.post(base_url, headers=headers, params=params, data=data)
            data = grequests.map([request])
            self.results = data[0].content.decode('UTF-8')
            soup = BeautifulSoup(self.results, 'html.parser')
            hosts = str(soup.find('pre')).splitlines()
            self.clean_hosts(hosts)
            params = (
                ('act', 'amass'),
            )
        except Exception as e:
            print(f'An exception has occurred: {e}')
        try:
            request = grequests.post(base_url, headers=headers, params=params, data=data)
            data = grequests.map([request])
            self.results = data[0].content.decode('UTF-8')
            soup = BeautifulSoup(self.results, 'html.parser')
            hosts = str(soup.find('pre')).splitlines()
            self.clean_hosts(hosts)
        except Exception as e:
            print(f'An exception has occurred: {e}')

    def get_hostnames(self) -> set:
        return self.totalhosts

    def process(self):
        self.do_search()
        print('\tSearching results.')

    def clean_hosts(self, soup_hosts):
        for host in soup_hosts:
            # print(type(host))
            host = str(host).strip()
            if len(host) > 1 and 'pre' not in host:
                if host[0] == '.':
                    self.totalhosts.add(host[1:])
                else:
                    self.totalhosts.add(host)


