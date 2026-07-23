import re
from collections.abc import Set

from theHarvester.lib.hostnames import normalize_scoped_hostname


class Parser:
    def __init__(self, results, word) -> None:
        self.results = results
        self.word = word
        self.temp: list = []

    async def generic_clean(self) -> None:
        self.results = (
            self.results.replace('<em>', '')
            .replace('<b>', '')
            .replace('</b>', '')
            .replace('</em>', '')
            .replace('%3a', '')
            .replace('<strong>', '')
            .replace('</strong>', '')
            .replace('<wbr>', '')
            .replace('</wbr>', '')
        )

        for search in (
            '<',
            '>',
            ':',
            '=',
            ';',
            '&',
            '%3A',
            '%3D',
            '%3C',
            '%2f',
            '/',
            '\\',
        ):
            self.results = self.results.replace(search, ' ')

    async def url_clean(self) -> None:
        self.results = self.results.replace('<em>', '').replace('</em>', '').replace('%2f', '').replace('%3a', '')
        for search in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C'):
            self.results = self.results.replace(search, ' ')

    async def emails(self):
        await self.generic_clean()
        # Local part is required, charset is flexible.
        # https://tools.ietf.org/html/rfc6531 (removed * and () as they provide FP mostly)
        candidates = re.findall(r"[a-zA-Z0-9.\-_+#~!$&']+@[a-zA-Z0-9.-]+", self.results)
        target = self.word.removeprefix('www.')
        emails: set[str] = set()
        for candidate in candidates:
            local_part, domain = candidate.lstrip('.').lower().split('@', maxsplit=1)
            if normalized_domain := normalize_scoped_hostname(domain, target):
                emails.add(f'{local_part}@{normalized_domain}')
        return emails

    async def fileurls(self, file) -> list:
        urls: list = []
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
        await self.generic_clean()
        target = self.word.removeprefix('www.')
        candidates = re.findall(r'[a-zA-Z0-9.-]+', self.results)
        hostnames = {
            normalized for candidate in candidates if (normalized := normalize_scoped_hostname(candidate.strip('.'), target))
        }
        return sorted(hostnames)

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
        found = re.finditer(r'(http|https)://(www\.)?trello.com/([a-zA-Z\d\-_.]+/?)*', self.results)
        urls = {match.group().strip() for match in found}
        return urls

    async def unique(self) -> list:
        return list(set(self.temp))
