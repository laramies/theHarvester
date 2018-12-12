import myparser
import re
import time
import requests

class search_exalead:
    def __init__(self, word, limit, start):
        self.word = word
        self.files = "pdf"
        self.results = ""
        self.totalresults = ""
        self.server = "www.exalead.com"
        self.hostname = "www.exalead.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/4.0"
        self.limit = limit
        self.counter = start

    def do_search(self):
        url = 'http:// ' + self.server + '/search/web/results/?q=%40' + self.word \
              + "&elements_per_page=50&start_index=" + str(self.counter)
        headers = {
            'Host': self.hostname,
            'Referer': ("http://" +self.hostname +"/search/web/results/?q=%40" +self.word),
            'User-agent': self.userAgent
        }
        h = requests.get(url=url, headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def do_search_files(self, files):
        url = 'http:// ' + self.server + '/search/web/results/?q=%40' + self.word \
              + "filetype:" + self.files + "&elements_per_page=50&start_index=" + str(self.counter)
        headers = {
            'Host': self.hostname,
            'Referer': ("http://" + self.hostname + "/search/web/results/?q=%40" + self.word),
            'User-agent': self.userAgent
        }
        h = requests.get(url=url, headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def check_next(self):
        renext = re.compile('topNextUrl')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = "1"
            print(str(self.counter))
        else:
            nexty = "0"
        return nexty

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_files(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.fileurls(self.files)

    def process(self):
        while self.counter <= self.limit:
            self.do_search()
            self.counter += 50
            print("\ tSearching " + str(self.counter) + " results...")

    def process_files(self, files):
        while self.counter < self.limit:
            self.do_search_files(files)
            time.sleep(1)
            more = self.check_next()
            if more == "1":
                self.counter += 50
            else:
                break
