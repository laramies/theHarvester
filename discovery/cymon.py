import random
import requests
import cymonparser

class search_cymon:

    def __init__(self, word):
        self.word = word
        self.url = ""
        self.results = ""
        self.server = "cymon.io"
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
        
    def do_search(self):
        try:
            headers = {'user-agent': random.choice(self.userAgent),'Accept':'*/*','Referer':self.url}
            response = requests.get(self.url, headers=headers)
            self.results = response.content
        except Exception as e:
            print(e)

    def process(self):
        try:
            self.url="https://" + self.server + "/domain/" + str(self.word)
            print("\tSearching Cymon results...")
            self.do_search()
        except Exception as e:
            print("Error occurred: " + str(e))

    def get_ipaddresses(self):
        try:
            ips = cymonparser.parser(self)
            return ips.search_ipaddresses()
        except Exception as e:
            print("Error occurred: " + str(e))
