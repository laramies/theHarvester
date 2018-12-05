import requests
import myparser
import time
import random

class search_crtsh:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "https://crt.sh/?q="
        self.userAgent = ["(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
            , ("Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) " +
            "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36"),
            ("Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) " +
             "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254"),
             "Mozilla/5.0 (SMART-TV; X11; Linux armv7l) AppleWebKit/537.42 (KHTML, like Gecko) Chromium/25.0.1349.2 Chrome/25.0.1349.2 Safari/537.42",
             "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"]
        self.quantity = "100"
        self.counter = 0

        

    def do_search(self):
        try:
            urly = self.server + self.word
        except Exception as e:
            print(e)
        try:
            params = {'User-Agent': random.choice(self.userAgent)}
            r=requests.get(urly,headers=params)
        except Exception as e:
            print(e)
        links = self.get_info(r.text)
        for link in links:
            params = {'User-Agent': random.choice(self.userAgent)}
            print ("\t\tSearching " + link)
            r = requests.get(link, headers=params)
            time.sleep(1)
            self.results = r.text
            self.totalresults += self.results

    """
    Function goes through text from base request and parses it for links
    @param text requests text
    @return list of links
    """
    def get_info(self,text):
        lines = []
        for line in str(text).splitlines():
            line = line.strip()
            if 'id=' in line:
                lines.append(line)
        links = []
        for i in range(len(lines)):
            if i % 2 == 0: #way html is formatted only care about every other one
                current = lines[i]
                current = current[43:] #43 is not an arbitrary number, the id number always starts at 43rd index
                link = ''
                for ch in current:
                    if ch == '"':
                        break
                    else:
                        link += ch
                links.append(('https://crt.sh?id=' + str(link)))
        return links

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()
        print("\tSearching CRT.sh results..")