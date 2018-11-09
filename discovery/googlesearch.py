import myparser
import time
import requests
import random

class search_google:

    def __init__(self, word, limit, start):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = "www.google.com"
        self.dorks = []
        self.links = []
        self.database = "https://www.google.com/search?q="
        self.userAgent = ["(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
          ,("Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) " +
          "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36"),
          ("Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) " +
          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254"),
          "Mozilla/5.0 (SMART-TV; X11; Linux armv7l) AppleWebKit/537.42 (KHTML, like Gecko) Chromium/25.0.1349.2 Chrome/25.0.1349.2 Safari/537.42"
          ,"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991"
          ,"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52"
          ,"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
          ,"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
          ,"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"]
        self.quantity = "100"
        self.limit = limit
        self.counter = start

    def do_search(self):
        try: #do normal scraping
            urly="http://" + self.server + "/search?num=" + self.quantity + "&start=" + str(self.counter) + "&hl=en&meta=&q=%40\"" + self.word + "\""
        except Exception, e:
            print e
        try:
            params = {'User-Agent': random.choice(self.userAgent)} #select random user agent
            r=requests.get(urly,params= params)
        except Exception,e:
            print e
        self.results = r.content
        self.totalresults += self.results

    def do_search_profiles(self):
        try:
            urly="http://" + self.server + "/search?num=" + self.quantity + "&start=" + str(self.counter) + "&hl=en&meta=&q=site:www.google.com%20intitle:\"Google%20Profile\"%20\"Companies%20I%27ve%20worked%20for\"%20\"at%20" + self.word + "\""
        except Exception, e:
            print e
        try:
            r=requests.get(urly)
        except Exception,e:
            print e
        self.results = r.content
        #'&hl=en&meta=&q=site:www.google.com%20intitle:"Google%20Profile"%20"Companies%20I%27ve%20worked%20for"%20"at%20' + self.word + '"')
        self.totalresults += self.results

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

    def process(self,google_dorking):
        if google_dorking == False:
            while self.counter <= self.limit and self.counter <= 1000:
                self.do_search()
                #more = self.check_next()
                time.sleep(1)
                print "\tSearching " + str(self.counter) + " results..."
                self.counter += 100
        else: #google dorking is true
            self.counter = 0 #reset counter
            print '\n'
            print "[-] Searching with Google Dorks: "
            while self.counter <= self.limit and self.counter <= 200: # only 200 dorks in list
                self.googledork() #call google dorking method if user wanted it!
                # more = self.check_next()
                time.sleep(.1)
                print "\tSearching " + str(self.counter) + " results..."
                self.counter += 100

    def process_profiles(self):
        while self.counter < self.limit:
            self.do_search_profiles()
            time.sleep(0.15)
            self.counter += 100
            print "\tSearching " + str(self.counter) + " results..."

    def append_dorks(self):
        try:  # wrap in try-except incase filepaths are messed up
            with open('wordlists/dorks.txt', mode='r') as fp:
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
        pipe = '%7C'
        # replace links with html encoding
        self.links = [self.database + space + self.word + space +
                      str(dork).replace(':', colon).replace('+', plus).replace('.', period).replace('"', double_quote)
                      .replace("*", asterick).replace('[', left_bracket).replace(']', right_bracket)
                      .replace('?', question_mark).replace(' ', space).replace('/', slash).replace("'", single_quote)
                      .replace("&", ampersand).replace('(', left_peren).replace(')', right_peren).replace('|', pipe)
                      for dork in self.dorks]

    def googledork(self):
        self.append_dorks()  # call functions to create list
        self.construct_dorks()
        if (self.counter >= 0 and self.counter <=100):
            self.send_dork(start=0, end=100)
        elif (self.counter >= 100 and self.counter <=200):
            self.send_dork(start=101, end=200)
        else: #only 200 dorks to prevent google from blocking ip
            pass

    def send_dork(self, start, end): # helper function to minimize code reusability
        params = {'User-Agent': random.choice(self.userAgent)}
        # get random user agent to try and prevent google from blocking ip
        for i in range(start, end):
            try:
                link = self.links[i] # get link from dork list
                req = requests.get(link, params=params)
                time.sleep(.15)  # sleep for a short time
                self.results = req.content
                self.totalresults += self.results
            except:
                continue
