import asyncio
import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchHunter:
    def __init__(self, word, limit: int | None, start) -> None:
        self.word = word
        self.requested_limit = limit
        self.limit = min(limit, 10) if limit is not None else 10
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
            logger.info('Hunter request failed without a response')
            return None
        if not 200 <= metadata.status < 300:
            logger.info(f'Hunter request failed with HTTP {metadata.status}')
            return None
        if not isinstance(metadata.body, dict):
            logger.info('Hunter returned malformed data')
            return None
        return metadata.body

    async def do_search(self) -> SourceExecutionReport | None:
        # First determine if a user account is not a free account, this call is free
        is_free = True
        headers = {'User-Agent': Core.get_user_agent()}
        acc_info_url = f'https://api.hunter.io/v2/account?api_key={self.key}'
        response = await self._fetch_json(acc_info_url, headers)
        if response is None:
            return None
        is_free = is_free if 'plan_name' in response['data'].keys() and response['data']['plan_name'].lower() == 'free' else False
        # Extract the total number of requests that are available for an account

        total_requests_avail = (
            response['data']['requests']['searches']['available'] - response['data']['requests']['searches']['used']
        )
        if is_free:
            response = await self._fetch_json(self.database, headers)
            if response is not None:
                self.emails, self.hostnames = await self.parse_resp(json_resp=response)
                entries = response.get('data', {}).get('emails', [])
                if (
                    isinstance(entries, list)
                    and len(entries) >= self.limit
                    and (self.requested_limit is None or self.requested_limit > self.limit)
                ):
                    return SourceExecutionReport('partial', 'provider-limit')
        else:
            # Determine the total number of emails that are available
            # As the most emails you can get within one query are 100
            # This is only done where paid accounts are in play
            hunter_dinfo_url = f'https://api.hunter.io/v2/email-count?domain={self.word}'
            response = await self._fetch_json(hunter_dinfo_url, headers)
            if response is None:
                return None
            available_results = max(0, response['data']['total'] - self.start)
            total_results = (
                min(available_results, self.requested_limit) if self.requested_limit is not None else available_results
            )
            total_number_reqs = (total_results + 99) // 100
            # Parse out meta field within initial JSON response to determine the total number of results
            quota_exhausted = total_requests_avail < total_number_reqs
            if quota_exhausted:
                logger.info('WARNING: account does not have enough requests to gather all emails')
                logger.info(
                    f'Total requests available: {total_requests_avail}, total requests needed to be made: {total_number_reqs}'
                )
            # max number of emails you can get per request is 100
            # increments of 100 with offset determining where to start
            # See docs for more details: https://hunter.io/api-documentation/v2#domain-search
            result_end = self.start + min(total_results, max(total_requests_avail, 0) * 100)
            for offset in range(self.start, result_end, 100):
                page_limit = min(100, result_end - offset)
                req_url = f'https://api.hunter.io/v2/domain-search?domain={self.word}&api_key={self.key}&limit={page_limit}&offset={offset}'
                response = await self._fetch_json(req_url, headers)
                if response is None:
                    return None
                temp_emails, temp_hostnames = await self.parse_resp(response)
                self.emails.extend(temp_emails)
                self.hostnames.extend(temp_hostnames)
                await asyncio.sleep(1)
            if quota_exhausted:
                return SourceExecutionReport('partial', 'quota-exhausted')
        return None

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

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()  # Only need to do it once.
        except AttributeError, KeyError, TypeError:
            logger.info('Hunter returned malformed data')
            return SourceExecutionReport('failed', 'invalid-response')

    async def get_emails(self):
        return self.emails

    async def get_hostnames(self):
        return self.hostnames
