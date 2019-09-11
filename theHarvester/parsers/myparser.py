import re


class Parser:

    def __init__(self, results, word):
        self.results = results
        self.word = word
        self.temp = []

    def genericClean(self):
        self.results = self.results.replace('<em>', '').replace('<b>', '').replace('</b>', '').replace('</em>', '')\
            .replace('%2f', '').replace('%3a', '').replace('<strong>', '').replace('</strong>', '')\
            .replace('<wbr>', '').replace('</wbr>', '')

        for e in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C', '/', '\\'):
            self.results = self.results.replace(e, ' ')

    def urlClean(self):
        self.results = self.results.replace('<em>', '').replace('</em>', '').replace('%2f', '').replace('%3a', '')
        for e in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C'):
            self.results = self.results.replace(e, ' ')

    def emails(self):
        self.genericClean()
        # Local part is required, charset is flexible.
        # https://tools.ietf.org/html/rfc6531 (removed * and () as they provide FP mostly)
        reg_emails = re.compile(r'[a-zA-Z0-9.\-_+#~!$&\',;=:]+' + '@' + '[a-zA-Z0-9.-]*' + self.word)
        self.temp = reg_emails.findall(self.results)
        emails = self.unique()
        return emails

    def fileurls(self, file):
        urls = []
        reg_urls = re.compile('<a href="(.*?)"')
        self.temp = reg_urls.findall(self.results)
        allurls = self.unique()
        for x in allurls:
            if x.count('webcache') or x.count('google.com') or x.count('search?hl'):
                pass
            else:
                urls.append(x)
        return urls

    def hostnames(self):
        self.genericClean()
        reg_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + self.word)
        self.temp = reg_hosts.findall(self.results)
        hostnames = self.unique()
        return hostnames

    def people_googleplus(self):
        self.results = re.sub('</b>', '', self.results)
        self.results = re.sub('<b>', '', self.results)
        reg_people = re.compile(r'>[a-zA-Z0-9._ ]* - Google\+')
        self.temp = reg_people.findall(self.results)
        resul = []
        for x in self.temp:
            y = x.replace(' | LinkedIn', '')
            y = y.replace(' profiles ', '')
            y = y.replace('LinkedIn', '')
            y = y.replace('"', '')
            y = y.replace('>', '')
            if y != " ":
                resul.append(y)
        return resul

    def hostnames_all(self):
        reg_hosts = re.compile('<cite>(.*?)</cite>')
        temp = reg_hosts.findall(self.results)
        for x in temp:
            if x.count(':'):
                res = x.split(':')[1].split('/')[2]
            else:
                res = x.split('/')[0]
            self.temp.append(res)
        hostnames = self.unique()
        return hostnames

    def links_linkedin(self):
        reg_links = re.compile(r"url=https:\/\/www\.linkedin.com(.*?)&")
        self.temp = reg_links.findall(self.results)
        resul = []
        for regex in self.temp:
            final_url = regex.replace("url=", "")
            resul.append("https://www.linkedin.com" + final_url)
        return resul

    def people_linkedin(self):
        reg_people = re.compile(r'">[a-zA-Z0-9._ -]* \| LinkedIn')
        self.temp = reg_people.findall(self.results)
        resul = []
        for x in (self.temp):
            y = x.replace(' | LinkedIn', '')
            y = y.replace(' profiles ', '')
            y = y.replace('LinkedIn', '')
            y = y.replace('"', '')
            y = y.replace('>', '')
            if y != " ":
                resul.append(y)
        return resul

    def people_twitter(self):
        reg_people = re.compile(r'(@[a-zA-Z0-9._ -]*)')
        self.temp = reg_people.findall(self.results)
        users = self.unique()
        resul = []
        for x in users:
            y = x.replace(' | LinkedIn', '')
            y = y.replace(' profiles ', '')
            y = y.replace('LinkedIn', '')
            y = y.replace('"', '')
            y = y.replace('>', '')
            if y != " ":
                resul.append(y)
        return resul

    def profiles(self):
        reg_people = re.compile(r'">[a-zA-Z0-9._ -]* - <em>Google Profile</em>')
        self.temp = reg_people.findall(self.results)
        resul = []
        for x in self.temp:
            y = x.replace(' <em>Google Profile</em>', '')
            y = y.replace('-', '')
            y = y.replace('">', '')
            if y != " ":
                resul.append(y)
        return resul

    def set(self):
        reg_sets = re.compile(r'>[a-zA-Z0-9]*</a></font>')
        self.temp = reg_sets.findall(self.results)
        sets = []
        for x in self.temp:
            y = x.replace('>', '')
            y = y.replace('</a</font', '')
            sets.append(y)
        return sets

    def urls(self):
        found = re.finditer(r'https://(www\.)?trello.com/([a-zA-Z0-9\-_\.]+/?)*', self.results)
        for x in found:
            self.temp.append(x.group())
        urls = self.unique()
        return urls

    def unique(self):
        self.new = []
        for x in self.temp:
            if x not in self.new:
                self.new.append(x)
        return self.new
