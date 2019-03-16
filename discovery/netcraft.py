#from lib.core import *
from parsers import myparser
import requests
import hashlib
import urllib
import re

class SearchNetcraft:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'netcraft.com'
        self.quantity = '100'
        self.counter = 0

    def do_search(self):
        # Module inspired by sublist3r
        session = requests.session()
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.8',
                'Accept-Encoding': 'gzip',
            }
            base_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host=example.com'
            cookies = {}
            r = session.get(base_url, headers=headers, cookies=cookies)
            cookie = str(r.cookies).split(" ")[1]
            cookies_list = cookie[0:cookie.find(';')].split("=")
            cookies[cookies_list[0]] = cookies_list[1]
            cookies['netcraft_js_verification_response'] = hashlib.sha1(urllib.unquote(cookies_list[1]).encode('utf-8')).hexdigest()
            #{'netcraft_js_verification_challenge': 'djF8TW9tb3crWWkyaWZWb1hySDU4VVJvWnByZ0NXbHcrQzhVTXVKc2UyeGpmeTlXdXpxWlA1TEdW%0AZjJHMndxVnE2SE5VeExoY1JubmdFOQpmQ2VwZG5EKzBnPT0KfDE1NTI3MDYwNjA%3D%0A%7C5a13284199e4dc7c260a16ae81ae2a717f4a274c', 'netcraft_js_verification_response': '9b87eaabe14a56f873e2212a9ab1cd846a5d1592'}
            print(cookies)
            #print(cookies); import sys;sys.exit(-2)
            search_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host=yale.edu'
            #r = session.get(search_url, cookies=cookies, headers=headers, timeout=25)
            while True:
                r = session.get(search_url, cookies=cookies, headers=headers, timeout=25)
                self.totalresults += r.text
                if 'Next page' not in r.text:
                    break
                search_url = self.get_next(r)
            print(r.text)
        except Exception as e:
            print('An exception has occured in netcraft: ' +str(e))

    def get_next(self, resp):
        link_regx = re.compile('<A href="(.*?)"><b>Next page</b></a>')
        link = link_regx.findall(resp)
        link = re.sub('host=.*?%s' % self.word, 'host=%s' % self.word, link[0])
        url = 'http://searchdns.netcraft.com' + link
        url = url.replace(' ', '%20')
        return url

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()
        print('\tSearching results.')

def main():
    n = SearchNetcraft(word="yale.edu")
    n.do_search()
    y = n.get_hostnames()
    for x in y:
        print(x)

main()
