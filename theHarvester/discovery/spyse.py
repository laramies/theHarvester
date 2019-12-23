from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
import requests


class SearchSpyse:

    def __init__(self, word):
        self.word = word
        self.key = Core.spyse_key()
        if self.key is None:
            raise MissingKey(True)
        self.results = ''
        self.totalresults = ''

    def do_search(self):
        try:
            base_url = f'https://api.spyse.com/v1/subdomains?domain={self.word}&api_token={self.key}&page=2'
            headers = {'User-Agent': Core.get_user_agent()}
            request = requests.get(base_url, headers=headers)
            self.results = request.json()
            # self.totalresults += self.results

        except Exception as e:
            print(f'An exception has occurred: {e}')

    def get_hostnames(self):
        return self.totalresults

    def process(self):
        self.do_search()
        print('\tSearching results.')
