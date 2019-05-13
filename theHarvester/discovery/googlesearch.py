from theHarvester.discovery.constants import *
from theHarvester.parsers import myparser
import requests
import time


class search_google:

    def __init__(self, word, limit, start):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = 'www.google.com'
        self.dorks = []
        self.links = []
        self.database = 'https://www.google.com/search?q='
        self.quantity = '100'
        self.limit = limit
        self.counter = start

    def do_search(self):
        try:  # Do normal scraping.
            urly = 'http://' + self.server + '/search?num=' + self.quantity + '&start=' + str(
                self.counter) + '&hl=en&meta=&q=%40\"' + self.word + '\"'
        except Exception as e:
            print(e)
        try:
            headers = {'User-Agent': googleUA}
            r = requests.get(urly, headers=headers)
        except Exception as e:
            print(e)
        self.results = r.text
        if search(self.results):
            time.sleep(getDelay() * 5)  # Sleep for a longer time.
        else:
            time.sleep(getDelay())
        self.totalresults += self.results

    def do_search_profiles(self):
        try:
            urly = 'http://' + self.server + '/search?num=' + self.quantity + '&start=' + str(
                self.counter) + '&hl=en&meta=&q=site:www.google.com%20intitle:\"Google%20Profile\"%20\"Companies%20I%27ve%20worked%20for\"%20\"at%20' + self.word + '\"'
        except Exception as e:
            print(e)
        try:
            headers = {'User-Agent': googleUA}
            r = requests.get(urly, headers=headers)
        except Exception as e:
            print(e)
        self.results = r.text
        if search(self.results):
            time.sleep(getDelay() * 5)  # Sleep for a longer time.
        else:
            time.sleep(getDelay())
        self.totalresults += self.results

    def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_files(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.fileurls(self.files)

    def get_profiles(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return rawres.profiles()

    def process(self, google_dorking):
        if google_dorking is False:
            while self.counter <= self.limit and self.counter <= 1000:
                self.do_search()
                print(f'\tSearching {self.counter} results.')
                self.counter += 100
        else:  # Google dorking is true.
            self.counter = 0  # Reset counter.
            print('\n')
            print('[-] Searching with Google Dorks: ')
            self.googledork()  # Call Google dorking method if user wanted it!

    def process_profiles(self):
        while self.counter < self.limit:
            self.do_search_profiles()
            time.sleep(getDelay())
            self.counter += 100
            print(f'\tSearching {self.counter} results.')

    def append_dorks(self):
        # Wrap in try-except incase filepaths are messed up.
        try:
            with open('wordlists/dorks.txt', mode='r') as fp:
                self.dorks = [dork.strip() for dork in fp]
        except FileNotFoundError as error:
            print(error)

    def construct_dorks(self):
        # Format is: site:targetwebsite.com + space + inurl:admindork
        colon = '%3A'
        plus = '%2B'
        space = '+'
        period = '%2E'
        double_quote = '%22'
        asterick = '%2A'
        left_bracket = '%5B'
        right_bracket = '%5D'
        question_mark = '%3F'
        slash = '%2F'
        single_quote = '%27'
        ampersand = '%26'
        left_peren = '%28'
        right_peren = '%29'
        pipe = '%7C'
        # Format is google.com/search?q=dork+space+self.word
        self.links = tuple(self.database +
                      str(dork).replace(':', colon).replace('+', plus).replace('.', period).replace('"', double_quote)
                      .replace('*', asterick).replace('[', left_bracket).replace(']', right_bracket)
                      .replace('?', question_mark).replace(' ', space).replace('/', slash).replace("'",single_quote)
                      .replace('&', ampersand).replace('(', left_peren).replace(')', right_peren).replace('|', pipe)
                      + space + self.word
                      for dork in self.dorks)

    def googledork(self):
        self.append_dorks()  # Call functions to create list.
        self.construct_dorks()
        self.send_dorks()

    def send_dorks(self):  # Helper function to minimize code reusability.
        headers = {'User-Agent': googleUA}
        # Get random user agent to try and prevent google from blocking IP.
        for num in range(len(self.links)):
            try:
                if num % 10 == 0 and num > 0:
                    print(f'\tSearching through {num} results')
                link = self.links[num]
                req = requests.get(link, headers=headers)
                self.results = req.text
                if search(self.results):
                    time.sleep(getDelay() * 5)  # Sleep for a longer time.
                else:
                    time.sleep(getDelay())
                self.totalresults += self.results
            except Exception as e:
                print(f'\tException Occurred {e}')
