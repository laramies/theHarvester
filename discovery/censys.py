import requests
import censysparser
import time
from discovery.constants import *

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
        
    def do_searchhosturl(self):
        try:
            headers = {'user-agent': getUserAgent(), 'Accept':'*/*','Referer': self.urlhost}       
            responsehost = requests.get(self.urlhost, headers=headers)
            self.resultshosts = responsehost.text
            self.total_resultshosts += self.resultshosts
        except Exception as e:
            print("Error occurred in the Censys module downloading pages from Censys - IP search: " + str(e))

    def do_searchcertificateurl(self):
        try:
            headers = {'user-agent': getUserAgent(), 'Accept':'*/*','Referer': self.urlcert}       
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

