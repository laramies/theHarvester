from theharvester.lib.core import *
from theharvester.parsers import myparser


class SearchSitedossier:

    def __init__(self, word):
        self.word = word
        self.totalresults = ""
        self.server = "www.sitedossier.com"
        self.hostname = "www.sitedossier.com"
        self.limit = 50

    def do_search(self):
        url = f"http://{self.server}/parentdomain/{self.word}"
        headers = {
            'User-Agent': Core.get_user_agent()
        }
        try:
            response = requests.get(url, headers=headers)
            self.totalresults += response.text
        except Exception as e:
            print(e)

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()
