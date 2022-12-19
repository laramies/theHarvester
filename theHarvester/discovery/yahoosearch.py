from theHarvester.lib.core import *
from theHarvester.parsers import myparser


class SearchYahoo:

    def __init__(self, word, limit) -> None:
        self.word = word
        self.total_results = ""
        self.server = 'search.yahoo.com'
        self.limit = limit
        self.proxy = False

    async def do_search(self) -> None:
        base_url = f'https://{self.server}/search?p=%40{self.word}&b=xx&pz=10'
        headers = {
            'Host': self.server,
            'User-agent': Core.get_user_agent()
        }
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
        for response in responses:
            self.total_results += response

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        toparse_emails = await rawres.emails()
        emails = set()
        # strip out numbers and dashes for emails that look like xxx-xxx-xxxemail@host.tld
        for email in toparse_emails:
            email = str(email)
            if '-' in email and email[0].isdigit() and email.index('-') <= 9:
                while email[0] == '-' or email[0].isdigit():
                    email = email[1:]
            emails.add(email)
        return list(emails)

    async def get_hostnames(self, proxy: bool = False):
        self.proxy = proxy
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
