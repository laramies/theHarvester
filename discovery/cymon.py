from discovery.constants import *
from lib.core import *
from parsers import cymonparser
import requests
import time


class search_cymon:

    def __init__(self, word):
        self.word = word
        self.url = ""
        self.results = ""
        self.server = 'cymon.io'

    def do_search(self):
        try:
            headers = {'user-agent': Core.get_user_agent(), 'Accept': '*/*', 'Referer': self.url}
            response = requests.get(self.url, headers=headers)
            time.sleep(getDelay())
            self.results = response.content
        except Exception as e:
            print(e)

    def process(self):
        try:
            self.url = 'https://' + self.server + '/domain/' + str(self.word)
            print('\tSearching results.')
            self.do_search()
        except Exception as e:
            print(f'Error occurred:  {e}')

    def get_ipaddresses(self):
        try:
            ips = cymonparser.Parser(self)
            return ips.search_ipaddresses()
        except Exception as e:
            print(f'Error occurred:  {e}')
