import asyncio
import logging

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport, SourceReportStatus

logger = logging.getLogger(__name__)


class SearchRocketReach:
    def __init__(self, word, limit: int | None) -> None:
        self.ips: set = set()
        self.word = word
        self.key = Core.rocketreach_key()
        if self.key is None:
            raise MissingKey('RocketReach')
        self.hosts: set = set()
        self.proxy = False
        self.baseurl = 'https://api.rocketreach.co/api/v2/person/search'
        self.urls: set = set()
        self.emails: set = set()
        self.limit = limit

    def _report(self, status: SourceReportStatus, reason: str) -> SourceExecutionReport:
        return SourceExecutionReport('partial' if self.urls or self.emails else status, reason)

    async def do_search(self) -> SourceExecutionReport | None:
        try:
            if self.limit is not None and self.limit <= 0:
                return

            headers = {
                'Api-Key': self.key,
                'Content-Type': 'application/json',
                'User-Agent': Core.get_user_agent(),
            }

            start = 0
            remaining = self.limit
            async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy, request_timeout=720) as session:
                while remaining is None or remaining > 0:
                    page_size = min(100, remaining) if remaining is not None else 100
                    data = {
                        'query': {'current_employer_domain': [self.word]},
                        'start': start,
                        'page_size': page_size,
                    }
                    response = await AsyncFetcher.post_fetch(
                        self.baseurl,
                        session=session,
                        headers=headers,
                        data=data,
                        json=True,
                        include_metadata=True,
                    )
                    if failure := provider_http_error(response):
                        logger.info('RocketReach request failed')
                        return self._report(*failure)
                    assert isinstance(response, FetcherResponse)
                    result = response.body
                    if not isinstance(result, dict):
                        logger.info('RocketReach returned malformed data')
                        return self._report('failed', 'invalid-response')

                    detail = result.get('detail', '')
                    if detail and 'Subscribe to a plan to access' in str(detail):
                        logger.info('RocketReach requires additional provider access')
                        return self._report('failed', 'quota-exhausted')

                    if detail and 'Request was throttled.' in str(detail):
                        # Rate limit has been triggered need to sleep extra
                        logger.info('RocketReach request was throttled')
                        return self._report('rate-limited', 'provider-rate-limit')

                    profiles = result.get('profiles')
                    if not isinstance(profiles, list):
                        logger.info('RocketReach returned malformed data')
                        return self._report('failed', 'invalid-response')
                    if not profiles:
                        break

                    malformed = False
                    for profile in profiles:
                        if not isinstance(profile, dict):
                            malformed = True
                            continue
                        linkedin_url = profile.get('linkedin_url')
                        if linkedin_url is not None:
                            if isinstance(linkedin_url, str) and linkedin_url.strip():
                                self.urls.add(linkedin_url)
                            else:
                                malformed = True
                        emails = profile.get('emails', [])
                        if not isinstance(emails, list):
                            malformed = True
                            continue
                        for email in emails:
                            if not isinstance(email, dict) or not isinstance(email.get('email'), str):
                                malformed = True
                                continue
                            if email['email'].strip():
                                self.emails.add(email['email'])
                    if malformed:
                        logger.info('RocketReach ignored malformed profile data')
                        return self._report('failed', 'invalid-response')

                    found = len(profiles)
                    if remaining is not None:
                        remaining -= found
                    start += found

                    pagination = result.get('pagination', {})
                    if not isinstance(pagination, dict):
                        return self._report('failed', 'invalid-response')
                    total = pagination.get('total')
                    if isinstance(total, int) and start >= total:
                        break
                    if found < page_size:
                        break

            await asyncio.sleep(get_delay() + 5)
            return None

        except OSError, RuntimeError, ValueError:
            logger.info('RocketReach request failed')
            return self._report('failed', 'transport-error')

    async def get_urls(self):
        return self.urls

    async def get_emails(self):
        return self.emails

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
