import asyncio
import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchTomba:
    def __init__(self, word, limit: int | None, start) -> None:
        self.word = word
        self.requested_limit = limit
        self.limit = min(limit, 10) if limit is not None else 10
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

    async def _fetch_json(self, url: str, headers: dict[str, str]) -> dict | None:
        response = await AsyncFetcher.fetch_all(
            [url],
            headers=headers,
            proxy=self.proxy,
            json=True,
            include_metadata=True,
        )
        metadata = response[0] if response and isinstance(response[0], FetcherResponse) else None
        if metadata is None:
            logger.info('Tomba request failed without a response')
            return None
        if not 200 <= metadata.status < 300:
            logger.info(f'Tomba request failed with HTTP {metadata.status}')
            return None
        if not isinstance(metadata.body, dict):
            logger.info('Tomba returned malformed data')
            return None
        return metadata.body

    async def do_search(self) -> SourceExecutionReport | None:
        # First determine if a user account is not a free account, this call is free
        is_free = True
        headers = {
            'User-Agent': Core.get_user_agent(),
            'X-Tomba-Key': self.key[0],
            'X-Tomba-Secret': self.key[1],
        }
        acc_info_url = 'https://api.tomba.io/v1/me'
        response = await self._fetch_json(acc_info_url, headers)
        if response is None:
            return None
        is_free = (
            is_free
            if 'name' in response['data']['pricing'].keys() and response['data']['pricing']['name'].lower() == 'free'
            else False
        )
        # Extract the total number of requests that are available for an account

        total_requests_avail = (
            response['data']['requests']['domains']['available'] - response['data']['requests']['domains']['used']
        )

        if is_free:
            page_size = 10
            total_results = self.limit
        else:
            tomba_counter = f'https://api.tomba.io/v1/email-count?domain={self.word}'
            response = await self._fetch_json(tomba_counter, headers)
            if response is None:
                return None
            available_results = max(0, response['data']['total'] - self.start)
            total_results = (
                min(available_results, self.requested_limit) if self.requested_limit is not None else available_results
            )
            page_size = 50

        first_page = self.start // page_size + 1
        first_page_skip = self.start % page_size
        total_number_reqs = (first_page_skip + total_results + page_size - 1) // page_size if total_results else 0
        quota_exhausted = total_requests_avail < total_number_reqs
        if quota_exhausted:
            logger.info('WARNING: The account does not have enough requests to gather all the emails.')

        remaining = total_results
        provider_limit_reached = False
        pages_to_fetch = min(total_number_reqs, max(total_requests_avail, 0))
        for page in range(first_page, first_page + pages_to_fetch):
            req_url = f'https://api.tomba.io/v1/domain-search?domain={self.word}&limit={page_size}&page={page}'
            response = await self._fetch_json(req_url, headers)
            if response is None:
                return None
            skip = first_page_skip if page == first_page else 0
            raw_entries = response['data']['emails']
            provider_limit_reached = is_free and isinstance(raw_entries, list) and len(raw_entries) >= page_size
            response['data']['emails'] = response['data']['emails'][skip : skip + remaining]
            temp_emails, temp_hostnames = await self.parse_resp(response)
            self.emails.extend(temp_emails)
            self.hostnames.extend(temp_hostnames)
            remaining -= len(response['data']['emails'])
            if not is_free:
                await asyncio.sleep(1)
        if quota_exhausted:
            return SourceExecutionReport('partial', 'quota-exhausted')
        if provider_limit_reached and (self.requested_limit is None or self.requested_limit > page_size):
            return SourceExecutionReport('partial', 'provider-limit')
        return None

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

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()  # Only need to do it once.
        except AttributeError, KeyError, TypeError:
            logger.info('Tomba returned malformed data')
            return SourceExecutionReport('failed', 'invalid-response')

    async def get_emails(self):
        return self.emails

    async def get_hostnames(self):
        return self.hostnames
