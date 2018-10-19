import myparser
import time
import requests
import random

class google_dork:

    def __init__(self, word, limit, start):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.dorks = []
        self.links = []
        self.database = "https://www.google.com/search?q="
        #create list of userAgents to shuffle through
        self.userAgent = ["(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
        ,("Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) " +
         "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36"),
         ("Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) " +
         "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254")]
        self.quantity = "100"
        self.limit = limit
        self.counter = start

    def append_dorks(self):
        try: #wrap in try-except incase filepaths are messed up
            with open('../theHarvester/wordlists/dorks.txt',mode='r') as fp:
                self.dorks = [dork.strip() for dork in fp]
        except IOError as error:
            print(error)

    def construct_dorks(self):
        #format is: site:targetwebsite.com + space + inurl:admindork
        colon = "%3A"
        plus = "%2B"
        space = '+'
        period = "%2E"
        double_quote = "%22"
        asterick = "%2A"
        left_bracket = "%5B"
        right_bracket = "%5D"
        question_mark = "%3F"
        slash = "%2F"
        single_quote = "%27"
        ampersand = "%26"
        left_peren = "%28"
        right_peren = "%29"
        #populate links list required that we need correct html encoding to work properly
        self.links = [self.database + space + self.word + space +
                      str(dork).replace(':', colon).replace('+', plus).replace('.', period).replace('"', double_quote)
                      .replace("*", asterick).replace('[', left_bracket).replace(']', right_bracket)
                      .replace('?', question_mark).replace(' ', space).replace('/', slash).replace("'", single_quote)
                      .replace("&", ampersand).replace('(', left_peren).replace(')', right_peren)
                      for dork in self.dorks]

    def do_search(self):
        for link in self.links:
              try:
                  params = {
                    'User-Agent': random.choice(self.userAgent) #grab random User-Agent to avoid google blocking ip
                  }
                  req = requests.get(link, params=params)
                  time.sleep(0.2)
                  self.results = req.content
                  self.totalresults += self.results
              except Exception: #if something happens just continue
                  continue

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_files(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.fileurls(self.files)

    def get_profiles(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.profiles()

    def process(self):
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            time.sleep(0.8)
            print "\tSearching " + str(self.counter) + " results..."
            self.counter += 100
