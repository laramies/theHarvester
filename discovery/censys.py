import random
import requests
import censysparser

class search_censys:

    def __init__(self, word):
        self.word = word
        self.urlhost = ""
        self.urlcert = ""
        self.page = ""
        self.resultshosts = ""
        self.resultcerts = ""
        self.total_resultshosts = ""
        self.total_resultscerts = ""
        self.server = "censys.io"
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
        
    def do_searchhosturl(self):
        try:
            headers = {'user-agent': random.choice(self.userAgent),'Accept':'*/*','Referer':self.urlhost}       
            responsehost = requests.get(self.urlhost, headers=headers)
            self.resultshosts = responsehost.text
            self.total_resultshosts += self.resultshosts
        except Exception as e:
            print("Error occurred in the Censys module downloading pages from Censys - IP search: " + str(e))

    def do_searchcertificateurl(self):
        try:
            headers = {'user-agent': random.choice(self.userAgent),'Accept':'*/*','Referer':self.urlcert}       
            responsecert = requests.get(self.urlcert, headers=headers)
            self.resultcerts = responsecert.text
            self.total_resultscerts += self.resultcerts
        except Exception as e:
            print("Error occurred in the Censys module downloading pages from Censys - certificates search: " + str(e))

    def process(self):
        try:
            self.urlhost = "https://" + self.server + "/ipv4/_search?q=" + str(self.word) + "&page=1"
            self.urlcert = "https://"+ self.server + "/certificates/_search?q=" + str(self.word) + "&page=1"
            self.do_searchhosturl()
            self.do_searchcertificateurl()
            counter = 2
            pages = censysparser.parser(self)
            totalpages = pages.search_numberofpageshosts()
            while counter <= totalpages:
                try:
                    self.page =str(counter)
                    self.urlhost = "https://" + self.server + "/ipv4/_search?q=" + str(self.word) + "&page=" + str(self.page)                   
                    print("\tSearching Censys IP results page " + self.page + "...")
                    self.do_searchhosturl()
                    counter+= 1
                except Exception as e:
                    print("Error occurred in the Censys module requesting the pages: " + str(e))
            counter = 2
            totalpages = pages.search_numberofpagescerts()
            while counter <= totalpages:
                try:
                    self.page =str(counter)
                    self.urlhost = "https://" + self.server + "/certificates/_search?q=" + str(self.word) + "&page=" + str(self.page)                   
                    print("\tSearching Censys certificates results page " + self.page + "...")
                    self.do_searchcertificateurl()
                    counter+= 1
                except Exception as e:
                    print("Error occurred in the Censys module requesting the pages: " + str(e))
        except Exception as e:
            print("Error occurred in the main Censys module: " + str(e))

    def get_hostnames(self):
        try:
            hostnames = censysparser.parser(self)
            hostnames_all = hostnames.search_hostnames()
            hostnames_all.extend(hostnames.search_hostnamesfromcerts())
            return hostnames_all
        except Exception as e:
            print("Error occurred in the Censys module - hostname search: " + str(e))

    def get_ipaddresses(self):
        try:
            ips = censysparser.parser(self)
            return ips.search_ipaddresses()
        except Exception as e:
            print("Error occurred in the main Censys module - IP address search: " + str(e))

