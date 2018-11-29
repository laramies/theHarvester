import random
import requests
import time
import censysparser

class search_censys:

    def __init__(self, word, limit):
        self.word = word
        self.limit = int(limit)
        self.results = ""
        self.total_results = ""
        self.server = "https://censys.io/"
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
            self.url = self.server + 'ipv4/_search?q=' + self.word
            headers = {'user-agent': random.choice(self.userAgent),'Accept':'*/*','Referer': self.url}
            response = requests.get(self.url, headers=headers)
            print("\tSearching Censys results..")
            self.results = response.text
            self.total_results += self.results
            pageLimit = self.get_pageLimit(self.total_results)
            if pageLimit != -1:
                for i in range(2, pageLimit+1):
                    try:
                        url = self.server + 'ipv4?q=' + self.word + '&page=' + str(i)
                        headers = {'user-agent': random.choice(self.userAgent), 'Accept': '*/*', 'Referer': url}
                        time.sleep(.5)
                        response = requests.get(url, headers=headers)
                        self.results = response.text
                        self.total_results += self.results
                    except Exception:
                        continue
        except Exception as e:
            print(e)

    def get_pageLimit(self, first_page_text):
        for line in str(first_page_text).strip().splitlines():
            if 'Page:' in line:
                line = line[18:] #where format is Page:1/# / is at index 18 and want everything after /
                return int(line)
        return -1


    def get_hostnames(self):
        try:
            hostnames = censysparser.parser(self)
            return hostnames.search_hostnames(self.total_results)
        except Exception as e:
            print("Error occurred: " + str(e))

    def get_ipaddresses(self):
        try:
            ips = censysparser.parser(self)
            return ips.search_ipaddresses()
        except Exception as e:
            print("Error occurred: " + str(e))
    
    def get_totalnumberofpages(self):
        try:
            pages = censysparser.parser(self)
            return pages.search_numberofpages()
        except Exception as e:
            print("Error occurred: " + str(e))

