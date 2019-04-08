from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests


class search_dnsdumpster:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = 'dnsdumpster.com'

    def do_search(self):
        try:
            agent = Core.get_user_agent()
            headers = {'User-Agent': agent}
            session = requests.session()
            # create a session to properly verify
            url = f'https://{self.server}'
            request = session.get(url, headers=headers)
            cookies = str(request.cookies)
            # extract csrftoken from cookies
            csrftoken = ''
            for ch in cookies.split("=")[1]:
                if ch == ' ':
                    break
                csrftoken += ch
            data = {
                'Cookie': f'csfrtoken={csrftoken}', 'csrfmiddlewaretoken': csrftoken, 'targetip': self.word}
            headers['Referer'] = url
            post_req = session.post(url, headers=headers, data=data)
            self.results = post_req.text
        except Exception as e:
            print(f'An exception occured: {e}')
        self.totalresults += self.results

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()  # Only need to do it once.
