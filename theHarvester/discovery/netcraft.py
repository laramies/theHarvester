from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests
import hashlib
import urllib.parse as urllib
import re

class SearchNetcraft:
    # this module was inspired by sublist3r's netcraft module

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.totalresults = ""
        self.server = 'netcraft.com'
        self.base_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'
        self.session = requests.session()
        self.headers = {
            'User-Agent': Core.get_user_agent()
        }
        self.timeout = 25
        self.domain = f"https://searchdns.netcraft.com/?restriction=site+ends+with&host={self.word}"

    def request(self, url, cookies=None):
        cookies = cookies or {}
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout, cookies=cookies)
        except Exception as e:
            print(e)
            resp = None
        return resp

    def get_next(self, resp):
        link_regx = re.compile('<A href="(.*?)"><b>Next page</b></a>')
        link = link_regx.findall(resp)
        link = re.sub(f'host=.*?{self.word}', f'host={self.domain}', link[0])
        url = f'http://searchdns.netcraft.com{link}'
        return url

    def create_cookies(self, cookie):
        cookies = dict()
        cookies_list = cookie[0:cookie.find(';')].split("=")
        cookies[cookies_list[0]] = cookies_list[1]
        # get js verification response
        cookies['netcraft_js_verification_response'] = hashlib.sha1(
            urllib.unquote(cookies_list[1]).encode('utf-8')).hexdigest()
        return cookies

    def get_cookies(self, headers):
        if 'set-cookie' in headers:
            cookies = self.create_cookies(headers['set-cookie'])
        else:
            cookies = {}
        return cookies

    def do_search(self):
        start_url = self.base_url
        resp = self.request(start_url)
        cookies = self.get_cookies(resp.headers)
        url = self.base_url.format(domain="yale.edu")
        while True:
            resp = self.request(url, cookies).text
            self.totalresults += resp
            if 'Next page' not in resp or resp is None:
                break
            url = self.get_next(resp)

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()