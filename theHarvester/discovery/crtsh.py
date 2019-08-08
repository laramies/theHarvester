#from theHarvester.lib.core import *
import requests


class SearchCrtsh:

    def __init__(self, word):
        self.word = word
        self.data = set()
        
    def do_search(self):
        url = f'https://crt.sh/?q=%25.{self.word}&output=json'
        request = requests.get(url)
        if request.ok:
            try:
                content = request.json()
                data = set([dct['name_value'][2:] if '*.' == dct['name_value'][:2] else dct['name_value'] for dct in content])
            except ValueError as error:
                print(f'Error when requesting data from crt.sh: {error}')

    def process(self):
        print('\tSearching results.')
        data = self.do_search()
        self.data = data

    def get_data(self):
        return self.data
