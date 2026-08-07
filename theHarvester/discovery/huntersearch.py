import asyncio
import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core

logger = logging.getLogger(__name__)


class SearchHunter:
    def __init__(self, word, limit, start) -> None:
        self.word = word
        self.requested_limit = limit
        self.limit = min(limit, 10)
        self.start = start
        key = Core.hunter_key()
        self.key = key.strip() if key else ''
        if not self.key:
            raise MissingKey('Hunter')
        self.total_results = ''
        self.counter = start
        self.database = (
            f'https://api.hunter.io/v2/domain-search?domain={self.word}&api_key={self.key}&limit={self.limit}&offset={self.start}'
        )
        self.proxy = False
        self.hostnames: list = []
        self.emails: list = []

    async def do_search(self) -> None:
        # First determine if a user account is not a free account, this call is free
        is_free = True
        headers = {'User-Agent': Core.get_user_agent()}
        acc_info_url = f'https://api.hunter.io/v2/account?api_key={self.key}'
        response = await AsyncFetcher.fetch_all([acc_info_url], headers=headers, proxy=self.proxy, json=True)
        is_free = (
            is_free if 'plan_name' in response[0]['data'].keys() and response[0]['data']['plan_name'].lower() == 'free' else False
        )
        # Extract the total number of requests that are available for an account

        total_requests_avail = (
            response[0]['data']['requests']['searches']['available'] - response[0]['data']['requests']['searches']['used']
        )
        if is_free:
            response = await AsyncFetcher.fetch_all([self.database], headers=headers, proxy=self.proxy, json=True)
            self.emails, self.hostnames = await self.parse_resp(json_resp=response[0])
        else:
            # Determine the total number of emails that are available
            # As the most emails you can get within one query are 100
            # This is only done where paid accounts are in play
            hunter_dinfo_url = f'https://api.hunter.io/v2/email-count?domain={self.word}'
            response = await AsyncFetcher.fetch_all([hunter_dinfo_url], headers=headers, proxy=self.proxy, json=True)
            total_results = min(max(0, response[0]['data']['total'] - self.start), self.requested_limit)
            total_number_reqs = (total_results + 99) // 100
            # Parse out meta field within initial JSON response to determine the total number of results
            if total_requests_avail < total_number_reqs:
                logger.info('WARNING: account does not have enough requests to gather all emails')
                logger.info(
                    f'Total requests available: {total_requests_avail}, total requests needed to be made: {total_number_reqs}'
                )
                logger.info('RETURNING current results, if you would still like to run this module comment out the if request')
                return
            # max number of emails you can get per request is 100
            # increments of 100 with offset determining where to start
            # See docs for more details: https://hunter.io/api-documentation/v2#domain-search
            result_end = self.start + total_results
            for offset in range(self.start, result_end, 100):
                page_limit = min(100, result_end - offset)
                req_url = f'https://api.hunter.io/v2/domain-search?domain={self.word}&api_key={self.key}&limit={page_limit}&offset={offset}'
                response = await AsyncFetcher.fetch_all([req_url], headers=headers, proxy=self.proxy, json=True)
                temp_emails, temp_hostnames = await self.parse_resp(response[0])
                self.emails.extend(temp_emails)
                self.hostnames.extend(temp_hostnames)
                await asyncio.sleep(1)

    async def parse_resp(self, json_resp):
        emails = list(sorted({email['value'] for email in json_resp['data']['emails']}))
        domains = list(
            sorted(
                {
                    source['domain']
                    for email in json_resp['data']['emails']
                    for source in email['sources']
                    if self.word in source['domain']
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
