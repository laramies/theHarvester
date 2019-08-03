from theHarvester.lib.core import *
import json
import requests


class SearchCrtsh:

    def __init__(self, word):
        self.word = word

    def do_search(self):
        url = f'https://crt.sh/?q=%{self.word}&output=json'
        request = requests.get(url, headers={'User-Agent': Core.get_user_agent()})

        if request.ok:
            try:
                content = request.content.decode('utf-8')
                data = json.loads(content)
                return data
            except ValueError as error:
                print(f'Error when requesting data from crt.sh: {error}')

    def process(self):
        self.do_search()
        print('\tSearching results.')

