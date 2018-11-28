import requests
import myparser

class search_crtsh:

    def __init__(self, word):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "https://crt.sh/?q="
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100116 Firefox/3.7"
        self.quantity = "100"
        self.counter = 0
        

    def do_search(self):
        try:
            urly = self.server + self.word
        except Exception as e:
            print(e)
        headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:34.0) Gecko/20100101 Firefox/34.0'}
        try:
            r=requests.get(urly,headers=headers)
        except Exception as e:
            print(e)
        links = self.get_info(r.text)
        for link in links:
            r = requests.get(link, headers=headers)
            for l in str(r.text).splitlines():
                if self.word in l:
                    print('concatting l to totalresults: ', l.replace('&nbsp','').replace(';',''))
                    self.totalresults += l

    def get_info(self,text):
        lines = []
        for line in str(text).splitlines():
            line = line.strip()
            if 'id=' in line:
                lines.append(line)
        links = []
        for i in range(len(lines)):
            if i % 2 == 0:
                current = lines[i]
                current = current[43:]
                link = ''
                for ch in current:
                    if ch == '"':
                        break
                    else:
                        link += ch
                links.append(('https://crt.sh?id=' + str(link)))
        return links


    def get_hostnames(self):
        rawres = myparser.parser(self.results, self.word)
        return rawres.hostnames()

    def process(self):
        self.do_search()
        print("\tSearching CRT.sh results..")