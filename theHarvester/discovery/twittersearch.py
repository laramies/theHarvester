from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import grequests
import re


class SearchTwitter:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.quantity = '100'
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        base_url = f'https://{self.server}/search?num=100&start=xx&hl=en&meta=&q=site%3Atwitter.com%20intitle%3A%22on+Twitter%22%20{self.word}'
        print(base_url)
        exit(-2)
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
            request = (grequests.get(url, headers=headers) for url in urls)
            response = grequests.imap(request, size=5)
            for entry in response:
                self.totalresults += entry.content.decode('UTF-8')
        except Exception as error:
            print(error)

    def get_people(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        to_parse = rawres.people_twitter()
        # fix invalid handles that look like @user other_output
        handles = set()
        for handle in to_parse:
            result = re.search(r'^@?(\w){1,15}', handle)
            if result:
                handles.add(result.group(0))
        return handles

    def process(self):
        self.do_search()

if __name__ == '__main__':
    #https://github.com/taspinar/twitterscraper
    import requests
    from bs4 import BeautifulSoup
    PROXY_URL = 'https://free-proxy-list.net/'

    response = requests.get(PROXY_URL)
    soup = BeautifulSoup(response.text, 'lxml')
    table = soup.find('table', id='proxylisttable')
    list_tr = table.find_all('tr')
    list_td = [elem.find_all('td') for elem in list_tr]
    list_td = list(filter(None, list_td))
    list_ip = [elem[0].text for elem in list_td]
    list_ports = [elem[1].text for elem in list_td]
    list_proxies = [':'.join(elem) for elem in list(zip(list_ip, list_ports))]
    import pprint as p
    p.pprint(list_proxies, indent=4)