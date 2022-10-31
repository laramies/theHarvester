from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
from typing import Union, List, Dict, Any, Optional, NamedTuple, Tuple
import asyncio
import aiohttp
import urllib.parse as urlparse
import random


class RetryResult(NamedTuple):
    time: float


class SuccessResult(NamedTuple):
    fragments: List[str]
    next_page: Optional[int]
    last_page: Optional[int]


class ErrorResult(NamedTuple):
    status_code: int
    body: Any


class SearchGithubCode:

    def __init__(self, word, limit) -> None:
        self.word = word
        self.total_results = ""
        self.server = 'api.github.com'
        self.limit = limit
        self.counter: int = 0
        self.page: int = 1
        self.key = Core.github_key()
        # If you don't have a personal access token, github narrows your search capabilities significantly
        # rate limits you more severely
        # https://developer.github.com/v3/search/#rate-limit
        if self.key is None:
            raise MissingKey('Github')
        self.proxy = False

    @staticmethod
    async def fragments_from_response(json_data: dict) -> List[str]:
        items: List[Dict[str, Any]] = json_data.get('items') or list()
        fragments: List[str] = list()
        for item in items:
            matches = item.get("text_matches") or list()
            for match in matches:
                fragments.append(match.get("fragment"))

        return [fragment for fragment in fragments if fragment is not None]

    @staticmethod
    async def page_from_response(page: str, links) -> Optional[Any]:
        page_link = links.get(page)
        if page_link:
            parsed = urlparse.urlparse(str(page_link.get("url")))
            params = urlparse.parse_qs(parsed.query)
            pages: List[Any] = params.get('page', [None])
            page_number = pages[0] and int(pages[0])
            return page_number
        else:
            return None

    async def handle_response(self, response: Tuple[str, dict, int, Any]) -> Union[ErrorResult, RetryResult, SuccessResult]:
        text, json_data, status, links = response
        if status == 200:
            results = await self.fragments_from_response(json_data)
            next_page = await self.page_from_response("next", links)
            last_page = await self.page_from_response("last", links)
            return SuccessResult(results, next_page, last_page)
        elif status == 429 or status == 403:
            return RetryResult(60)
        else:
            try:
                return ErrorResult(status, json_data)
            except ValueError:
                return ErrorResult(status, text)

    async def do_search(self, page: int) -> Tuple[str, dict, int, Any]:
        if page is None:
            url = f'https://{self.server}/search/code?q="{self.word}"'
        else:
            url = f'https://{self.server}/search/code?q="{self.word}"&page={page}'
        headers = {
            'Host': self.server,
            'User-agent': Core.get_user_agent(),
            'Accept': "application/vnd.github.v3.text-match+json",
            'Authorization': f'token {self.key}'
        }

        async with aiohttp.ClientSession(headers=headers) as sess:
            if self.proxy:
                async with sess.get(url, proxy=random.choice(Core.proxy_list())) as resp:
                    return await resp.text(), await resp.json(), resp.status, resp.links
            else:
                async with sess.get(url) as resp:
                    return await resp.text(), await resp.json(), resp.status, resp.links

    @staticmethod
    async def next_page_or_end(result: SuccessResult) -> int:
        if result.next_page is not None:
            return result.next_page
        else:
            return result.last_page

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        try:
            while self.counter <= self.limit and self.page is not None:
                api_response = await self.do_search(self.page)
                result = await self.handle_response(api_response)
                if isinstance(result, SuccessResult):
                    print(f'\tSearching {self.counter} results.')
                    for fragment in result.fragments:
                        self.total_results += fragment
                        self.counter = self.counter + 1
                    self.page = await self.next_page_or_end(result)
                    await asyncio.sleep(get_delay())
                elif isinstance(result, RetryResult):
                    sleepy_time = get_delay() + result.time
                    print(f'\tRetrying page in {sleepy_time} seconds...')
                    await asyncio.sleep(sleepy_time)
                elif isinstance(result, ErrorResult):
                    raise Exception(f"\tException occurred: status_code: {result.status_code} reason: {result.body}")
                else:
                    raise Exception("\tUnknown exception occurred")
        except Exception as e:
            print(f'An exception has occurred: {e}')

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
