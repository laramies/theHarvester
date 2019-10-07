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

        for search in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C', '/', '\\'):
            self.results = self.results.replace(search, ' ')

    def urlClean(self):
        self.results = self.results.replace('<em>', '').replace('</em>', '').replace('%2f', '').replace('%3a', '')
        for search in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C'):
            self.results = self.results.replace(search, ' ')

    def emails(self):
        self.genericClean()
        # Local part is required, charset is flexible.
        # https://tools.ietf.org/html/rfc6531 (removed * and () as they provide FP mostly)
        reg_emails = re.compile(r'[a-zA-Z0-9.\-_+#~!$&\',;=:]+' + '@' + '[a-zA-Z0-9.-]*' + self.word.replace('www.', ''))
        self.temp = reg_emails.findall(self.results)
        emails = self.unique()
        true_emails = {str(email)[1:].lower().strip() if len(str(email)) > 1 and str(email)[0] == '.'
                       else len(str(email)) > 1 and str(email).lower().strip() for email in emails}
        # if email starts with dot shift email string and make sure all emails are lowercase
        return true_emails

    def fileurls(self, file):
        urls = []
        reg_urls = re.compile('<a href="(.*?)"')
        self.temp = reg_urls.findall(self.results)
        allurls = self.unique()
        for iteration in allurls:
            if iteration.count('webcache') or iteration.count('google.com') or iteration.count('search?hl'):
                pass
            else:
                urls.append(iteration)
        return urls

    def hostnames(self):
        self.genericClean()
        reg_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + self.word)
        self.temp = reg_hosts.findall(self.results)
        hostnames = self.unique()
        reg_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + self.word.replace('www.', ''))
        self.temp = reg_hosts.findall(self.results)
        hostnames.extend(self.unique())
        return list(set(hostnames))

    def people_googleplus(self):
        self.results = re.sub('</b>', '', self.results)
        self.results = re.sub('<b>', '', self.results)
        reg_people = re.compile(r'>[a-zA-Z0-9._ ]* - Google\+')
        self.temp = reg_people.findall(self.results)
        resul = []
        for iteration in self.temp:
            delete = iteration.replace(' | LinkedIn', '')
            delete = delete.replace(' profiles ', '')
            delete = delete.replace('LinkedIn', '')
            delete = delete.replace('"', '')
            delete = delete.replace('>', '')
            if delete != " ":
                resul.append(delete)
        return resul

    def hostnames_all(self):
        reg_hosts = re.compile('<cite>(.*?)</cite>')
        temp = reg_hosts.findall(self.results)
        for iteration in temp:
            if iteration.count(':'):
                res = iteration.split(':')[1].split('/')[2]
            else:
                res = iteration.split('/')[0]
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
        for iteration in (self.temp):
            delete = iteration.replace(' | LinkedIn', '')
            delete = delete.replace(' profiles ', '')
            delete = delete.replace('LinkedIn', '')
            delete = delete.replace('"', '')
            delete = delete.replace('>', '')
            if delete != " ":
                resul.append(delete)
        return resul

    def people_twitter(self):
        reg_people = re.compile(r'(@[a-zA-Z0-9._ -]*)')
        self.temp = reg_people.findall(self.results)
        users = self.unique()
        resul = []
        for iteration in users:
            delete = iteration.replace(' | LinkedIn', '')
            delete = delete.replace(' profiles ', '')
            delete = delete.replace('LinkedIn', '')
            delete = delete.replace('"', '')
            delete = delete.replace('>', '')
            if delete != " ":
                resul.append(delete)
        return resul

    def profiles(self):
        reg_people = re.compile(r'">[a-zA-Z0-9._ -]* - <em>Google Profile</em>')
        self.temp = reg_people.findall(self.results)
        resul = []
        for iteration in self.temp:
            delete = iteration.replace(' <em>Google Profile</em>', '')
            delete = delete.replace('-', '')
            delete = delete.replace('">', '')
            if delete != " ":
                resul.append(delete)
        return resul

    def set(self):
        reg_sets = re.compile(r'>[a-zA-Z0-9]*</a></font>')
        self.temp = reg_sets.findall(self.results)
        sets = []
        for iteration in self.temp:
            delete = iteration.replace('>', '')
            delete = delete.replace('</a</font', '')
            sets.append(delete)
        return sets

    def urls(self):
        found = re.finditer(r'(http|https)://(www\.)?trello.com/([a-zA-Z0-9\-_\.]+/?)*', self.results)
        urls = {match.group().strip() for match in found}
        return urls

    def unique(self) -> list:
        return list(set(self.temp))
