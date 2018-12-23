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
        self.ips = []
        self.hostnamesall = []
        
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
                    self.page = str(counter)
                    self.urlhost = "https://" + self.server + "/certificates/_search?q=" + str(self.word) + "&page=" + str(self.page)                   
                    print("\tSearching Censys certificates results page " + self.page + "...")
                    self.do_searchcertificateurl()
                    counter += 1
                except Exception as e:
                    print("Error occurred in the Censys module requesting the pages: " + str(e))
        except Exception as e:
            print("Error occurred in the main Censys module: " + str(e))

    def get_hostnames(self):
        try:
            ips = self.get_ipaddresses()
            headers = {'user-agent': getUserAgent(), 'Accept':'*/*','Referer': self.urlcert}
            response = requests.post("https://censys.io/ipv4/getdns", json={"ips": ips}, headers=headers)
            responsejson = response.json()
            for key, jdata in responsejson.items():
                    if jdata is not None:
                        self.hostnamesall.append(jdata)
                    else:
                        pass
            hostnamesfromcerts = censysparser.parser(self)
            self.hostnamesall.extend(hostnamesfromcerts.search_hostnamesfromcerts())
            return self.hostnamesall
        except Exception as e:
            print("Error occurred in the Censys module - hostname search: " + str(e))

    def get_ipaddresses(self):
        try:
            ips = censysparser.parser(self)
            self.ips = ips.search_ipaddresses()
            return self.ips
        except Exception as e:
            print("Error occurred in the main Censys module - IP address search: " + str(e))

