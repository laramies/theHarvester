from theHarvester.lib.core import *
from lxml import html
import requests
import re


class SearchGooglefile:

    def __init__(self, word):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.start = 0
        self.links = set()

    def do_search(self):
        filetype = ['doc', 'docx', 'pdf', 'ppt', 'pptx', 'txt', 'xls', 'xlsx']
        regex = re.compile(r'(?P<urls>http\S{3}\w+\S+)(?P<junk>&prev=search)', re.MULTILINE.IGNORECASE, )
        headers = {
            'Host': f'{self.server}',
            'User-agent': Core.get_user_agent(),
            'Referrer': "google.com"
        }

        for doc_type in filetype:
            url = f'https://www.google.com/search?hl=en&q=site%3A{self.word}%20filetype%3A{doc_type}&num=100&start={self.start}'
            page = requests.get(url, headers=headers)
            tree = html.fromstring(page.content)
            self.results = tree.xpath('//*[@class="r"]/a/@href')
            # print('results: ', self.results)
        for link in self.results:
            match = re.search(regex, link)
            if match:
                # print('type: ', type(match.group('urls')))
                self.links.update(set(list(match.group('urls'))))
                # print(match.group('urls'))
            else:
                # print('not matched')
                # print(f'{link}')
                self.links.add(link)
        if self.results:
            self.start += 100

    def get_links(self) -> set:
        return self.links

    def process(self):
        self.do_search()
        print(f'\tSearching results.')
