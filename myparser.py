import string
import re


class parser:

    def __init__(self, results, word):
        self.results = results
        self.word = word
        self.temp = []

    def genericClean(self):
        self.results = re.sub('<em>', '', self.results)
        self.results = re.sub('<b>', '', self.results)
        self.results = re.sub('</b>', '', self.results)
        self.results = re.sub('</em>', '', self.results)
        self.results = re.sub('%2f', ' ', self.results)
        self.results = re.sub('%3a', ' ', self.results)
        self.results = re.sub('<strong>', '', self.results)
        self.results = re.sub('</strong>', '', self.results)
        self.results = re.sub('<wbr>','',self.results)
        self.results = re.sub('</wbr>','',self.results)


        for e in ('>', ':', '=', '<', '/', '\\', ';', '&', '%3A', '%3D', '%3C'):
            self.results = string.replace(self.results, e, ' ')

    def urlClean(self):
        self.results = re.sub('<em>', '', self.results)
        self.results = re.sub('</em>', '', self.results)
        self.results = re.sub('%2f', ' ', self.results)
        self.results = re.sub('%3a', ' ', self.results)

        for e in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C'):
            self.results = string.replace(self.results, e, ' ')

    def emails(self):
        self.genericClean()
        reg_emails = re.compile(
            # Local part is required, charset is flexible
           # https://tools.ietf.org/html/rfc6531 (removed * and () as they provide FP mostly )
            '[a-zA-Z0-9.\-_+#~!$&\',;=:]+' +
            '@' +
            '[a-zA-Z0-9.-]*' +
            self.word)
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

    def people_googleplus(self):
        self.results = re.sub('</b>', '', self.results)
        self.results = re.sub('<b>', '', self.results)
        reg_people = re.compile('>[a-zA-Z0-9._ ]* - Google\+')
        #reg_people = re.compile('">[a-zA-Z0-9._ -]* profiles | LinkedIn')
        self.temp = reg_people.findall(self.results)
        resul = []
        for x in self.temp:
            y = string.replace(x, ' | LinkedIn', '')
            y = string.replace(y, ' profiles ', '')
            y = string.replace(y, 'LinkedIn', '')
            y = string.replace(y, '"', '')
            y = string.replace(y, '>', '')
            if y != " ":
                resul.append(y)
        return resul



    def people_twitter(self):
        reg_people = re.compile('(@[a-zA-Z0-9._ -]*)')
        #reg_people = re.compile('">[a-zA-Z0-9._ -]* profiles | LinkedIn')
        self.temp = reg_people.findall(self.results)
        users = self.unique()
        resul = []
        for x in users:
            y = string.replace(x, ' | LinkedIn', '')
            y = string.replace(y, ' profiles ', '')
            y = string.replace(y, 'LinkedIn', '')
            y = string.replace(y, '"', '')
            y = string.replace(y, '>', '')
            if y != " ":
                resul.append(y)
        return resul

    def people_linkedin(self):
        reg_people = re.compile('">[a-zA-Z0-9._ -]* \| LinkedIn')
        #reg_people = re.compile('">[a-zA-Z0-9._ -]* profiles | LinkedIn')
        self.temp = reg_people.findall(self.results)
        resul = []
        for x in self.temp:
            y = string.replace(x, ' | LinkedIn', '')
            y = string.replace(y, ' profiles ', '')
            y = string.replace(y, 'LinkedIn', '')
            y = string.replace(y, '"', '')
            y = string.replace(y, '>', '')
            if y != " ":
                resul.append(y)
        return resul

    def profiles(self):
        reg_people = re.compile('">[a-zA-Z0-9._ -]* - <em>Google Profile</em>')
        self.temp = reg_people.findall(self.results)
        resul = []
        for x in self.temp:
            y = string.replace(x, ' <em>Google Profile</em>', '')
            y = string.replace(y, '-', '')
            y = string.replace(y, '">', '')
            if y != " ":
                resul.append(y)
        return resul

    def people_jigsaw(self):
        res = []
        #reg_people = re.compile("'tblrow' title='[a-zA-Z0-9.-]*'><span class='nowrap'/>")
        reg_people = re.compile(
            "href=javascript:showContact\('[0-9]*'\)>[a-zA-Z0-9., ]*</a></span>")
        self.temp = reg_people.findall(self.results)
        for x in self.temp:
            a = x.split('>')[1].replace("</a", "")
            res.append(a)
        return res

    def hostnames(self):
        self.genericClean()
        reg_hosts = re.compile('[a-zA-Z0-9.-]*\.' + self.word)
        self.temp = reg_hosts.findall(self.results)
        hostnames = self.unique()
        return hostnames

    def set(self):
        reg_sets = re.compile('>[a-zA-Z0-9]*</a></font>')
        self.temp = reg_sets.findall(self.results)
        sets = []
        for x in self.temp:
            y = string.replace(x, '>', '')
            y = string.replace(y, '</a</font', '')
            sets.append(y)
        return sets

    def hostnames_all(self):
        reg_hosts = re.compile('<cite>(.*?)</cite>')
        temp = reg_hosts.findall(self.results)
        for x in temp:
            if x.count(':'):
                res = x.split(':')[1].split('/')[2]
            else:
                res = x.split("/")[0]
            self.temp.append(res)
        hostnames = self.unique()
        return hostnames

    def unique(self):
        self.new = []
        for x in self.temp:
            if x not in self.new:
                self.new.append(x)
        return self.new
