from bs4 import BeautifulSoup
import re

class parser:
    
    def __init__(self, results):
        self.results = results
        self.ipaddresses = []
        self.soup = BeautifulSoup(results.results,features="html.parser")
        self.hostnames = []
        self.numberofpages = 0

    def search_hostnames(self):
        try:
            hostnamelist = self.soup.findAll('tt')
            for hostnameitem in hostnamelist:
                self.hostnames.append(hostnameitem.text)
            return self.hostnames
        except Exception,e:
            print("Error occurred: " + e) 

    def search_ipaddresses(self):
        try:
            ipaddresslist = self.soup.findAll('a','SearchResult__title-text')
            for ipaddressitem in ipaddresslist:
                self.ipaddresses.append(ipaddressitem.text.strip())
            return self.ipaddresses
        except Exception,e:
            print("Error occurred: " + e)

    def search_numberofpages(self):
        try:
            items = self.soup.findAll(href=re.compile("page"))
            for item in items:
                if (item.text !='next'):            #to filter out pagination
                    self.numberofpages+=1
            return self.numberofpages
        except Exception,e:
            print("Error occurred: " + e)
