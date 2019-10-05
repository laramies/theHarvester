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

        for symbol in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C', '/', '\\'):
            self.results = self.results.replace(symbol, ' ')

    def urlClean(self):
        self.results = self.results.replace('<em>', '').replace('</em>', '').replace('%2f', '').replace('%3a', '')
        for symbol in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C'):
            self.results = self.results.replace(symbol, ' ')

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
        for testurl in allurls:
            if testurl.count('webcache') or testurl.count('google.com') or testurl.count('search?hl'):
                pass
            else:
                urls.append(testurl)
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
        for profile in self.temp:
            new_profile = profile.replace(' | LinkedIn', '')
            new_profile = new_profile.replace(' profiles ', '')
            new_profile = new_profile.replace('LinkedIn', '')
            new_profile = new_profile.replace('"', '')
            new_profile = new_profile.replace('>', '')
            if new_profile != " ":
                resul.append(new_profile)
        return resul

    def hostnames_all(self):
        reg_hosts = re.compile('<cite>(.*?)</cite>')
        temp = reg_hosts.findall(self.results)
        for fhost in temp:
            if fhost.count(':'):
                res = fhost.split(':')[1].split('/')[2]
            else:
                res = fhost.split('/')[0]
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
        for profile in (self.temp):
            new_profile = profile.replace(' | LinkedIn', '')
            new_profile = new_profile.replace(' profiles ', '')
            new_profile = new_profile.replace('LinkedIn', '')
            new_profile = new_profile.replace('"', '')
            new_profile = new_profile.replace('>', '')
            if new_profile != " ":
                resul.append(new_profile)
        return resul

    def people_twitter(self):
        reg_people = re.compile(r'(@[a-zA-Z0-9._ -]*)')
        self.temp = reg_people.findall(self.results)
        users = self.unique()
        resul = []
        for t_user in users:
            n_user = t_user.replace(' | LinkedIn', '')
            n_user = n_user.replace(' profiles ', '')
            n_user = n_user.replace('LinkedIn', '')
            n_user = n_user.replace('"', '')
            n_user = n_user.replace('>', '')
            if n_user != " ":
                resul.append(n_user)
        return resul

    def profiles(self):
        reg_people = re.compile(r'">[a-zA-Z0-9._ -]* - <em>Google Profile</em>')
        self.temp = reg_people.findall(self.results)
        resul = []
        for profile in self.temp:
            rprofile = profile.replace(' <em>Google Profile</em>', '')
            rprofile = rprofile.replace('-', '')
            rprofile = rprofile.replace('">', '')
            if rprofile != " ":
                resul.append(rprofile)
        return resul

    def set(self):
        reg_sets = re.compile(r'>[a-zA-Z0-9]*</a></font>')
        self.temp = reg_sets.findall(self.results)
        sets = []
        for fset in self.temp:
            nset = fset.replace('>', '')
            nset = nset.replace('</a</font', '')
            sets.append(nset)
        return sets

    def urls(self):
        found = re.finditer(r'(http|https)://(www\.)?trello.com/([a-zA-Z0-9\-_\.]+/?)*', self.results)
        urls = {match.group().strip() for match in found}
        return urls

    def unique(self) -> list:
        self.new = []
        for uself in self.temp:
            if uself not in self.new:
                self.new.append(uself)
        return self.new
