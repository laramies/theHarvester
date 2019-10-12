from theHarvester.lib.core import *
from bs4 import BeautifulSoup
import requests


class SearchSuip:

    def __init__(self, word: str):
        self.word: str = word
        self.results: str = ''
        self.totalresults: str = ''
        self.totalhosts: set = set()
        self.totalips: set = set()

    def do_search(self):
        headers = {'User-Agent': Core.get_user_agent()}
        params = (
            ('act', 'subfinder'),
        )

        data = {
            'url': self.word.replace('www.', ''),
            'Submit1': 'Submit'
        }
        response = requests.post('https://suip.biz/', headers=headers, params=params, data=data)
        soup = BeautifulSoup(response.text, 'html.parser')
        hosts: list = str(soup.find('pre')).splitlines()
        self.clean_hosts(hosts)
        params = (
            ('act', 'amass'),
        )
        # change act to amass now
        response = requests.post('https://suip.biz/', headers=headers, params=params, data=data)
        soup = BeautifulSoup(response.text, 'html.parser')
        hosts: list = str(soup.find('pre')).splitlines()
        self.clean_hosts(hosts)

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
