import re
from bs4 import BeautifulSoup


class Parser:

    def __init__(self, results):
        self.results = results
        self.ipaddresses = []
        self.soup = BeautifulSoup(results.results, features='html.parser')

    def search_ipaddresses(self):
        try:
            tags = self.soup.findAll('td')
            allip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(tags))
            self.ipaddresses = set(allip)
            return self.ipaddresses
        except Exception as e:
            print('Error occurred: ' + str(e))
