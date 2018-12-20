from bs4 import BeautifulSoup
import re


class parser:
    
    def __init__(self, resultstoparse):
        self.ipaddresses = []
        self.souphosts = BeautifulSoup(resultstoparse.total_resultshosts,features="html.parser")
        self.soupcerts = BeautifulSoup(resultstoparse.total_resultscerts,features="html.parser")
        self.hostnames = []
        self.hostnamesfromcerts = []
        self.urls = []
        self.numberofpageshosts = 0
        self.numberofpagescerts = 0

    def search_hostnames(self):
        try:
            hostnamelist = self.souphosts.findAll('tt')
            for hostnameitem in hostnamelist:
                self.hostnames.append(hostnameitem.text)
            print ("FOUND HOSTNAMES:" + str(self.hostnames))
            return self.hostnames
        except Exception as e:
            print("Error occurred in the Censys module: hostname parser: " + str(e))

    def search_hostnamesfromcerts(self):
        try:
            hostnamelist = self.soupcerts.findAll("i", "fa fa-fw fa-home")
            for hostnameitem in hostnamelist:
                hostitems = hostnameitem.next_sibling
                hostnames = str(hostitems)
                hostnamesclean = re.sub('[ \'\[\]]','', hostnames)
                hostnamesclean = re.sub(r'\.\.\.',r'',hostnamesclean)
                self.hostnamesfromcerts.extend(hostnamesclean.split(","))
            self.hostnamesfromcerts = list(filter(None, self.hostnamesfromcerts))   #filter out duplicates
            print ("FOUND HOSTNAMESFROMCERTS:" + str(self.hostnamesfromcerts))
            return self.hostnamesfromcerts
        except Exception as e:
            print("Error occurred in the Censys module: certificate hostname parser: " + str(e))

    def search_ipaddresses(self):
        try:
            ipaddresslist = self.souphosts.findAll('a','SearchResult__title-text')
            for ipaddressitem in ipaddresslist:
                self.ipaddresses.append(ipaddressitem.text.strip())
            return self.ipaddresses
        except Exception as e:
            print("Error occurred in the Censys module: IP address parser: " + str(e))

    def search_numberofpageshosts(self):
        try:
            items = self.souphosts.findAll(href=re.compile("page"))
            for item in items:
                if (item.text !='next'):            #to filter out pagination
                    self.numberofpageshosts+=1
            return self.numberofpageshosts
        except Exception as e:
            print("Error occurred in the Censys module IP search: page parser: " + str(e))

    def search_numberofpagescerts(self):
        try:
            items = self.soupcerts.findAll(href=re.compile("page"))
            for item in items:
                if (item.text != 'next'):            #to filter out pagination
                    self.numberofpagescerts += 1
            return self.numberofpagescerts
        except Exception as e:
            print("Error occurred in the Censys module certificate search: page parser: " + str(e))

              
   
