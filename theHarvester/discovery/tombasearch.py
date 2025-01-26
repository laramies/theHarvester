import asyncio

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchTomba:
    def __init__(self, word, limit, start) -> None:
        self.word = word
        self.limit = limit
        self.limit = 10 if limit > 10 else limit
        self.start = start
        self.key = Core.tomba_key()
        if self.key[0] is None or self.key[1] is None:
            raise MissingKey('Tomba Key and/or Secret')
        self.total_results = ''
        self.counter = start
        self.database = f'https://api.tomba.io/v1/domain-search?domain={self.word}&limit=10'
        self.proxy = False
        self.hostnames: list = []
        self.emails: list = []

    async def do_search(self) -> None:
        # First determine if a user account is not a free account, this call is free
        is_free = True
        headers = {
            'User-Agent': Core.get_user_agent(),
            'X-Tomba-Key': self.key[0],
            'X-Tomba-Secret': self.key[1],
        }
        acc_info_url = 'https://api.tomba.io/v1/me'
        response = await AsyncFetcher.fetch_all([acc_info_url], headers=headers, json=True)
        is_free = (
            is_free
            if 'name' in response[0]['data']['pricing'].keys() and response[0]['data']['pricing']['name'].lower() == 'free'
            else False
        )
        # Extract the total number of requests that are available for an account

        total_requests_avail = (
            response[0]['data']['requests']['domains']['available'] - response[0]['data']['requests']['domains']['used']
        )

        if is_free:
            response = await AsyncFetcher.fetch_all([self.database], headers=headers, proxy=self.proxy, json=True)
            self.emails, self.hostnames = await self.parse_resp(json_resp=response[0])
        else:
            # Determine the total number of emails that are available
            # As the most emails you can get within one query are 100
            # This is only done where paid accounts are in play
            tomba_counter = f'https://api.tomba.io/v1/email-count?domain={self.word}'
            response = await AsyncFetcher.fetch_all([tomba_counter], headers=headers, proxy=self.proxy, json=True)
            total_number_reqs = response[0]['data']['total'] // 100
            # Parse out meta field within initial JSON response to determine the total number of results
            if total_requests_avail < total_number_reqs:
                print('WARNING: The account does not have enough requests to gather all the emails.')
                print(f'Total requests available: {total_requests_avail}, total requests needed to be made: {total_number_reqs}')
                print(
                    'RETURNING current results, If you still wish to run this module despite the current results, please comment out the "if request" line.'
                )
                return
            self.limit = 100
            # max number of emails you can get per request
            # increments of max number with page determining where to start
            # See docs for more details: https://developer.tomba.io/#domain-search
            for page in range(0, total_number_reqs + 1):
                req_url = f'https://api.tomba.io/v1/domain-search?domain={self.word}&limit={self.limit}&page={page}'
                response = await AsyncFetcher.fetch_all([req_url], headers=headers, proxy=self.proxy, json=True)
                temp_emails, temp_hostnames = await self.parse_resp(response[0])
                self.emails.extend(temp_emails)
                self.hostnames.extend(temp_hostnames)
                await asyncio.sleep(1)

    async def parse_resp(self, json_resp):
        emails = list(sorted({email['email'] for email in json_resp['data']['emails']}))
        domains = list(
            sorted(
                {
                    source['website_url']
                    for email in json_resp['data']['emails']
                    for source in email['sources']
                    if self.word in source['website_url']
                }
            )
        )
        return emails, domains

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()  # Only need to do it once.

    async def get_emails(self):
        return self.emails

    async def get_hostnames(self):
        return self.hostnames
