from theHarvester.lib.core import *
import requests


class SearchCertspoter:

    def __init__(self, word):
        self.word = word
        self.totalhosts = set()

    def do_search(self) -> None:
        base_url = f'https://api.certspotter.com/v1/issuances?domain={self.word}&expand=dns_names'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            request = requests.get(base_url, headers=headers)
            response = request.json()
            for dct in response:
                for key, value in dct.items():
                    if key == 'dns_names':
                        self.totalhosts.update({name for name in value if name})
        except Exception as e:
            print(e)

    def get_hostnames(self) -> set:
        return self.totalhosts

    def process(self):
        self.do_search()
        print('\tSearching results.')
