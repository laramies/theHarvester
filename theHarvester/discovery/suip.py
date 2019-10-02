from theHarvester.lib.core import *
import grequests
from bs4 import BeautifulSoup

class SearchSuip:

    def __init__(self, word: str):
        self.word: str = word
        self.results: str = ''
        self.totalresults: str = ''
        self.totalhosts: set = set()
        self.totalips: set = set()

    def do_search(self):
        base_url: str = "https://suip.biz/"
        params = (
            ('act', 'subfinder'),
        )

        data = {
            'url': self.word.replace('www.', ''),
            'Submit1': 'Submit'
        }

        headers: dict = {'User-Agent': Core.get_user_agent()}
        try:
            #request = grequests.post(base_url, headers=headers, params=params, data=data)
            #data = grequests.map([request])
            #self.results = data[0].content.decode('UTF-8')
            #soup = BeautifulSoup(self.results, 'html.parser')
            #hosts: list = str(soup.find('pre')).splitlines()
            #self.clean_hosts(hosts)
            pass
        except Exception as e:
            print(f'An exception has occurred: {e}')
        try:
            params = (
                ('act', 'amass'),
            )
            request = grequests.post(base_url, headers=headers, params=params, data=data)
            data = grequests.map([request])
            self.results = data[0].content.decode('UTF-8')
            soup = BeautifulSoup(self.results, 'html.parser')
            print(soup.prettify())
            hosts: list = str(soup.find('pre')).splitlines()
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
            host = str(host).strip()
            if len(host) > 1 and 'pre' not in host:
                if host[0] == '.':
                    self.totalhosts.add(host[1:])
                else:
                    self.totalhosts.add(host)


