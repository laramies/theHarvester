import asyncio
import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core

logger = logging.getLogger(__name__)


class SearchTomba:
    def __init__(self, word, limit, start) -> None:
        self.word = word
        self.requested_limit = limit
        self.limit = min(limit, 10)
        self.start = start
        key, secret = Core.tomba_key()
        self.key = (key.strip() if key else '', secret.strip() if secret else '')
        if not all(self.key):
            raise MissingKey('Tomba Key and/or Secret')
        self.total_results = ''
        self.counter = start
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
        response = await AsyncFetcher.fetch_all([acc_info_url], headers=headers, proxy=self.proxy, json=True)
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
            page_size = 10
            total_results = self.limit
        else:
            tomba_counter = f'https://api.tomba.io/v1/email-count?domain={self.word}'
            response = await AsyncFetcher.fetch_all([tomba_counter], headers=headers, proxy=self.proxy, json=True)
            total_results = min(max(0, response[0]['data']['total'] - self.start), self.requested_limit)
            page_size = 50

        first_page = self.start // page_size + 1
        first_page_skip = self.start % page_size
        total_number_reqs = (first_page_skip + total_results + page_size - 1) // page_size if total_results else 0
        if total_requests_avail < total_number_reqs:
            logger.info('WARNING: The account does not have enough requests to gather all the emails.')
            return

        remaining = total_results
        for page in range(first_page, first_page + total_number_reqs):
            req_url = f'https://api.tomba.io/v1/domain-search?domain={self.word}&limit={page_size}&page={page}'
            response = await AsyncFetcher.fetch_all([req_url], headers=headers, proxy=self.proxy, json=True)
            skip = first_page_skip if page == first_page else 0
            response[0]['data']['emails'] = response[0]['data']['emails'][skip : skip + remaining]
            temp_emails, temp_hostnames = await self.parse_resp(response[0])
            self.emails.extend(temp_emails)
            self.hostnames.extend(temp_hostnames)
            remaining -= len(response[0]['data']['emails'])
            if not is_free:
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
