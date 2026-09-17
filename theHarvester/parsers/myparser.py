import re

from theHarvester.lib.hostnames import normalize_scoped_hostname


class Parser:
    def __init__(self, results, word) -> None:
        self.results = results
        self.word = word

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
            '%2F',
            '/',
            '\\',
        ):
            self.results = self.results.replace(search, ' ')

    async def emails(self):
        await self.generic_clean()
        # Local part is required, charset is flexible.
        # https://tools.ietf.org/html/rfc6531 (removed * and () as they provide FP mostly)
        candidates = re.findall(r"[a-zA-Z0-9.\-_+#~!$&']+@[a-zA-Z0-9.-]+", self.results)
        emails: set[str] = set()
        for candidate in candidates:
            local_part, domain = candidate.lstrip('.').lower().split('@', maxsplit=1)
            if normalized_domain := normalize_scoped_hostname(domain, self.word):
                emails.add(f'{local_part}@{normalized_domain}')
        return emails

    async def hostnames(self):
        await self.generic_clean()
        candidates = re.findall(r'[a-zA-Z0-9.-]+', self.results)
        hostnames = {
            normalized for candidate in candidates if (normalized := normalize_scoped_hostname(candidate.strip('.'), self.word))
        }
        return sorted(hostnames)
