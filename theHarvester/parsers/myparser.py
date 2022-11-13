import re
from typing import Set, List


class Parser:

    def __init__(self, results, word) -> None:
        self.results = results
        self.word = word
        self.temp: List = []

    async def genericClean(self) -> None:
        self.results = self.results.replace('<em>', '').replace('<b>', '').replace('</b>', '').replace('</em>', '') \
            .replace('%3a', '').replace('<strong>', '').replace('</strong>', '') \
            .replace('<wbr>', '').replace('</wbr>', '')

        for search in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C', '%2f', '/', '\\'):
            self.results = self.results.replace(search, ' ')

    async def urlClean(self) -> None:
        self.results = self.results.replace('<em>', '').replace('</em>', '').replace('%2f', '').replace('%3a', '')
        for search in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C'):
            self.results = self.results.replace(search, ' ')

    async def emails(self):
        await self.genericClean()
        # Local part is required, charset is flexible.
        # https://tools.ietf.org/html/rfc6531 (removed * and () as they provide FP mostly)
        reg_emails = re.compile(r'[a-zA-Z0-9.\-_+#~!$&\',;=:]+' + '@' + '[a-zA-Z0-9.-]*' + self.word.replace('www.', ''))
        self.temp = reg_emails.findall(self.results)
        emails = await self.unique()
        true_emails = {str(email)[1:].lower().strip() if len(str(email)) > 1 and str(email)[0] == '.'
                       else len(str(email)) > 1 and str(email).lower().strip() for email in emails}
        # if email starts with dot shift email string and make sure all emails are lowercase
        return true_emails

    async def fileurls(self, file) -> List:
        urls: List = []
        reg_urls = re.compile('<a href="(.*?)"')
        self.temp = reg_urls.findall(self.results)
        allurls = await self.unique()
        for iteration in allurls:
            if iteration.count('webcache') or iteration.count('google.com') or iteration.count('search?hl'):
                pass
            else:
                urls.append(iteration)
        return urls

    async def hostnames(self):
        await self.genericClean()
        reg_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + self.word)
        self.temp = reg_hosts.findall(self.results)
        hostnames = await self.unique()
        reg_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + self.word.replace('www.', ''))
        self.temp = reg_hosts.findall(self.results)
        hostnames.extend(await self.unique())
        return list(set(hostnames))

    async def hostnames_all(self):
        reg_hosts = re.compile('<cite>(.*?)</cite>')
        temp = reg_hosts.findall(self.results)
        for iteration in temp:
            if iteration.count(':'):
                res = iteration.split(':')[1].split('/')[2]
            else:
                res = iteration.split('/')[0]
            self.temp.append(res)
        hostnames = await self.unique()
        return hostnames

    async def set(self):
        reg_sets = re.compile(r'>[a-zA-Z\d]*</a></font>')
        self.temp = reg_sets.findall(self.results)
        sets = []
        for iteration in self.temp:
            delete = iteration.replace('>', '')
            delete = delete.replace('</a</font', '')
            sets.append(delete)
        return sets

    async def urls(self) -> Set[str]:
        found = re.finditer(r'(http|https)://(www\.)?trello.com/([a-zA-Z\d\-_\.]+/?)*', self.results)
        urls = {match.group().strip() for match in found}
        return urls

    async def unique(self) -> list:
        return list(set(self.temp))
