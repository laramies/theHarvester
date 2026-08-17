import asyncio
import logging
import urllib.parse as urlparse
from typing import TYPE_CHECKING, Any, NamedTuple

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser

if TYPE_CHECKING:
    import aiohttp

logger = logging.getLogger(__name__)


class RetryResult(NamedTuple):
    time: float


class SuccessResult(NamedTuple):
    fragments: list[str]
    next_page: int
    last_page: int


class ErrorResult(NamedTuple):
    status_code: int
    body: Any


class SearchGithubCode:
    def __init__(self, word, limit) -> None:
        try:
            self.word = word
            self.total_results = ''
            self.server = 'api.github.com'
            self.limit = limit
            self.counter = 0
            self.page = 1
            self.key = Core.github_key()
            if self.key is None:
                raise MissingKey('Github')
            self.proxy = False
            self.base_url = f'https://{self.server}/search/code?q="{self.word}"'
            self.headers = {
                'Host': self.server,
                'User-agent': Core.get_user_agent(),
                'Accept': 'application/vnd.github.v3.text-match+json',
                'Authorization': f'token {self.key}',
            }
            # Retry control to avoid infinite loops on rate limiting
            self.retry_count = 0
            self.max_retries = 3
        except Exception as e:
            logger.info(f'Error initializing SearchGithubCode: {e}')
            raise

    @staticmethod
    async def fragments_from_response(json_data: dict) -> list[str]:
        items = json_data.get('items', [])
        if not isinstance(items, list):
            return []

        fragments: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            text_matches = item.get('text_matches', [])
            if not isinstance(text_matches, list):
                continue
            for match in text_matches:
                if not isinstance(match, dict):
                    continue
                fragment = match.get('fragment')
                if isinstance(fragment, str) and fragment:
                    fragments.append(fragment)
        return fragments

    @staticmethod
    async def page_from_response(page: str, links) -> int | None:
        try:
            if page_link := links.get(page):
                parsed = urlparse.urlparse(str(page_link.get('url')))
                if page_param := urlparse.parse_qs(parsed.query).get('page', [None])[0]:
                    return int(page_param)
            return 0
        except Exception as e:
            logger.info(f'Error parsing page response: {e}')
            return None

    async def handle_response(self, response: tuple[str, dict, int, Any]) -> ErrorResult | RetryResult | SuccessResult:
        try:
            text, json_data, status, links = response
            if status == 200:
                results = await self.fragments_from_response(json_data)
                # Ensure next_page and last_page default to 0 if None
                next_page = await self.page_from_response('next', links) or 0
                last_page = await self.page_from_response('last', links) or 0
                return SuccessResult(results, next_page, last_page)
            if status in (429, 403):
                return RetryResult(60)
            return ErrorResult(status, json_data if isinstance(json_data, dict) else text)
        except Exception as e:
            logger.info(f'Error handling response: {e}')
            return ErrorResult(500, str(e))

    @staticmethod
    async def next_page_or_end(result: SuccessResult) -> int | None:
        if result.next_page is not None:
            return result.next_page
        else:
            return result.last_page

    async def do_search(
        self,
        page: int,
        session: aiohttp.ClientSession | None = None,
    ) -> tuple[str, dict, int, Any]:
        try:
            if session is None:
                async with AsyncFetcher.open_session(headers=self.headers, proxy=self.proxy) as owned_session:
                    return await self.do_search(page, owned_session)
            url = f'{self.base_url}&page={page}' if page else self.base_url
            async with session.get(url) as resp:
                return await resp.text(), await resp.json(), resp.status, resp.links
        except Exception as e:
            logger.info(f'Error performing search: {e}')
            return '', {}, 500, {}

    async def process(self, proxy: bool = False) -> None:
        try:
            self.proxy = proxy
            async with AsyncFetcher.open_session(headers=self.headers, proxy=self.proxy) as session:
                while self.counter < self.limit and self.page != 0:
                    try:
                        api_response = await self.do_search(self.page, session)
                        result = await self.handle_response(api_response)

                        if isinstance(result, SuccessResult):
                            # Reset retry counter on any successful response
                            self.retry_count = 0
                            logger.info(f'\tSearching {self.counter} results.')
                            remaining = self.limit - self.counter
                            fragments = result.fragments[:remaining]
                            if not fragments:
                                self.page = 0
                                break
                            self.total_results += f'{" ".join(fragments)} '
                            self.counter += len(fragments)
                            if self.counter >= self.limit:
                                self.page = 0
                                break
                            next_or_last = result.next_page or result.last_page
                            # Break if pagination does not advance to avoid infinite loop
                            if next_or_last == self.page:
                                logger.info('\tNo page advancement detected; exiting to avoid infinite loop.')
                                self.page = 0
                                break
                            self.page = next_or_last
                            await asyncio.sleep(get_delay())
                        elif isinstance(result, RetryResult):
                            self.retry_count += 1
                            if self.retry_count > self.max_retries:
                                logger.info('\tMaximum retries reached; exiting to avoid infinite loop.')
                                self.page = 0
                                break
                            sleepy_time = get_delay() + result.time
                            logger.info(f'\tRetrying page in {sleepy_time} seconds...')
                            await asyncio.sleep(sleepy_time)
                        else:
                            # On error, stop to avoid endless retries on a bad state
                            logger.info(f'\tGitHub code API request failed with status {result.status_code}')
                            self.page = 0
                            break
                    except Exception as e:
                        logger.info(f'Error processing page: {e}')
                        await asyncio.sleep(get_delay())
        except Exception as e:
            logger.info(f'An exception has occurred in githubcode process: {e}')

    async def get_emails(self):
        try:
            rawres = myparser.Parser(self.total_results, self.word)
            return await rawres.emails()
        except Exception as e:
            logger.info(f'Error getting emails: {e}')
            return []

    async def get_hostnames(self):
        try:
            rawres = myparser.Parser(self.total_results, self.word)
            return await rawres.hostnames()
        except Exception as e:
            logger.info(f'Error getting hostnames: {e}')
            return []
