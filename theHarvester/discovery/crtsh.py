from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests
import time


class SearchCrtsh:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'https://crt.sh/?q='
        self.quantity = '100'
        self.counter = 0

    def do_search(self):
        try:
            urly = self.server + self.word
        except Exception as e:
            print(e)
        try:
            params = {'User-Agent': Core.get_user_agent()}
            r = requests.get(urly, headers=params)
        except Exception as e:
            print(e)
        links = self.get_info(r.text)
        for link in links:
            params = {'User-Agent': Core.get_user_agent()}
            r = requests.get(link, headers=params)
            time.sleep(getDelay())
            self.results = r.text
            self.totalresults += self.results

    """
    Function goes through text from base request and parses it for links
    @param text requests text
    @return list of links
    """
    def get_info(self, text):
        lines = []
        for line in str(text).splitlines():
            line = line.strip()
            if 'id=' in line:
                lines.append(line)
        links = []
        for i in range(len(lines)):
            if i % 2 == 0:  # Way html is formatted only care about every other one.
                current = lines[i]
                current = current[43:]  # 43 is not an arbitrary number, the id number always starts at 43rd index.
                link = ''
                for ch in current:
                    if ch == '"':
                        break
                    else:
                        link += ch
                links.append(('https://crt.sh?id=' + str(link)))
        return links

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()
        print('\tSearching results.')
