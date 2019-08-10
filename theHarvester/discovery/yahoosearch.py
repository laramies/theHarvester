import grequests
from theHarvester.lib.core import *
from theHarvester.parsers import myparser


class SearchYahoo:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = 'search.yahoo.com'
        self.limit = limit

    def do_search(self):
        base_url = f'https://{self.server}/search?p=%40{self.word}&b=xx&pz=10'
        headers = {
            'Host': self.server,
            'User-agent': Core.get_user_agent()
        }
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
        request = (grequests.get(url, headers=headers) for url in urls)
        response = grequests.imap(request, size=5)
        for entry in response:
            self.total_results += entry.content.decode('UTF-8')

    def process(self):
        self.do_search()

    def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        toparse_emails = rawres.emails()
        emails = set()
        # strip out numbers and dashes for emails that look like xxx-xxx-xxxemail@host.tld
        for email in toparse_emails:
            email = str(email)
            if '-' in email and email[0].isdigit() and email.index('-') <= 9:
                while email[0] == '-' or email[0].isdigit():
                    email = email[1:]
            emails.add(email)
        return list(emails)

    def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.hostnames()
