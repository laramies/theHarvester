from theHarvester.lib.core import *
import requests


class SearchCrtsh:

    def __init__(self, word):
        self.word = word
        self.data = set()

    def do_search(self):
        try:
            data = set()
            url = f'https://crt.sh/?q=%25.{self.word}&output=json'
            headers = {'User-Agent': Core.get_user_agent()}
            request = requests.get(url, headers=headers, timeout=15)
            if request.ok:
                content = request.json()
                data = set(
                    [dct['name_value'][2:] if '*.' == dct['name_value'][:2] else dct['name_value'] for dct in content])
                return data
            return data
        except Exception as e:
            print(f'An exception has occurred in crtsh: {e}')

    def process(self):
        print('\tSearching results.')
        data = self.do_search()
        self.data = data

    def get_data(self):
        return self.data
