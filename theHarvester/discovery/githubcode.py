import asyncio
import random
import urllib.parse as urlparse
from typing import Any, NamedTuple

import aiohttp

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.core import Core
from theHarvester.parsers import myparser


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
        except Exception as e:
            print(f'Error initializing SearchGithubCode: {e}')
            raise

    @staticmethod
    async def fragments_from_response(json_data: dict) -> list[str]:
        try:
            return [
                match['fragment']
                for item in json_data.get('items', [])
                for match in item.get('text_matches', [])
                if match.get('fragment') is not None
            ]
        except Exception as e:
            print(f'Error extracting fragments: {e}')
            return []

    @staticmethod
    async def page_from_response(page: str, links) -> int | None:
        try:
            if page_link := links.get(page):
                parsed = urlparse.urlparse(str(page_link.get('url')))
                if page_param := urlparse.parse_qs(parsed.query).get('page', [None])[0]:
                    return int(page_param)
            return 0
        except Exception as e:
            print(f'Error parsing page response: {e}')
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
            print(f'Error handling response: {e}')
            return ErrorResult(500, str(e))

    @staticmethod
    async def next_page_or_end(result: SuccessResult) -> int | None:
        if result.next_page is not None:
            return result.next_page
        else:
            return result.last_page

    async def do_search(self, page: int) -> tuple[str, dict, int, Any]:
        try:
            url = f'{self.base_url}&page={page}' if page else self.base_url
            async with aiohttp.ClientSession(headers=self.headers) as sess:
                async with sess.get(url, proxy=random.choice(Core.proxy_list()) if self.proxy else None) as resp:
                    return await resp.text(), await resp.json(), resp.status, resp.links
        except Exception as e:
            print(f'Error performing search: {e}')
            return '', {}, 500, {}

    async def process(self, proxy: bool = False) -> None:
        try:
            self.proxy = proxy
            while self.counter <= self.limit and self.page is not None:
                try:
                    api_response = await self.do_search(self.page)
                    result = await self.handle_response(api_response)

                    if isinstance(result, SuccessResult):
                        print(f'\tSearching {self.counter} results.')
                        self.total_results += ''.join(result.fragments)
                        self.counter += len(result.fragments)
                        self.page = result.next_page or result.last_page
                        await asyncio.sleep(get_delay())
                    elif isinstance(result, RetryResult):
                        sleepy_time = get_delay() + result.time
                        print(f'\tRetrying page in {sleepy_time} seconds...')
                        await asyncio.sleep(sleepy_time)
                    else:
                        print(f'\tException occurred: status_code: {result.status_code} reason: {result.body}')
                except Exception as e:
                    print(f'Error processing page: {e}')
                    await asyncio.sleep(get_delay())
        except Exception as e:
            print(f'An exception has occurred in githubcode process: {e}')

    async def get_emails(self):
        try:
            rawres = myparser.Parser(self.total_results, self.word)
            return await rawres.emails()
        except Exception as e:
            print(f'Error getting emails: {e}')
            return []

    async def get_hostnames(self):
        try:
            rawres = myparser.Parser(self.total_results, self.word)
            return await rawres.hostnames()
        except Exception as e:
            print(f'Error getting hostnames: {e}')
            return []
