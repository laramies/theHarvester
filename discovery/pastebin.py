import myparser
import time
import requests

class search_pastebin:

    def __init__(self, word, limit, start):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = "www.googleapis.com"
        self.hostname = "www.googleapis.com"
        self.userAgent = "Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "10"
        self.limit = limit
        self.counter = 1
        self.api_key = "" # Google CSE API key
        self.cse_id = ""  # Google CSE Engine ID
        self.lowRange = start
        self.highRange = start+100

        self.do_search()

    def do_search(self):
        while self.counter <= self.limit and self.counter <= 1000:
            try:
                url = (
                    "https://" + self.server +
                    "/customsearch/v1?key=" + self.api_key +
                    "&highRange=" + str(self.highRange) +
                    "&lowRange=" + str(self.lowRange) +
                    "&cx=" + self.cse_id +
                    "&start=" + str(self.counter) +
                    "&q=%40\"" + self.word + "\""
                )
                r = requests.get(url, headers={'User-Agent': self.userAgent})
            except Exception,e:
                print e
            self.results = r.content
            self.totalresults += self.results
            time.sleep(1)
            print "\tSearching " + str(self.counter) + " results..."
            if self.counter == 101:
                self.counter = 1
                self.lowRange +=100
                self.highRange +=100
            else:
                self.counter += 10
            tracker=self.counter + self.lowRange

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
