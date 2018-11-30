import myparser
import re
import requests
# http://www.jigsaw.com/SearchAcrossCompanies.xhtml?opCode=refresh&rpage=4&mode=0&cnCountry=&order=0&orderby=0&cmName=accuvant&cnDead=false&cnExOwned=false&count=0&screenNameType=0&screenName=&omitScreenNameType=0&omitScreenName=&companyId=0&estimatedCount=277&rowsPerPage=50

class search_jigsaw:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.jigsaw.com"
        self.hostname = "www.jigsaw.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        url = 'http://' + self.server + "/FreeTextSearch.xhtml?opCode=search&autoSuggested=True&freeText=" + self.word
        headers = {
            'User-agent': self.userAgent
        }
        h = requests.get(url=url, headers=headers)
        self.results = h.text
        self.totalresults += self.results

    def check_next(self):
        renext = re.compile('>  Next  <')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = "1"
        else:
            nexty = "0"
        return nexty

    def get_people(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.people_jigsaw()

    def process(self):
        while (self.counter < self.limit):
            self.do_search()
            more = self.check_next()
            if more == "1":
                self.counter += 100
            else:
                break
