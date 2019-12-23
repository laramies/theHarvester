from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
import requests
from requests import Response
import time
from typing import List, Dict, Any, Optional, NamedTuple
import urllib.parse as urlparse


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

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = 'api.github.com'
        self.limit = limit
        self.counter = 0
        self.page = 1
        self.key = Core.github_key()
        # If you don't have a personal access token, github narrows your search capabilities significantly
        # rate limits you more severely
        # https://developer.github.com/v3/search/#rate-limit
        if self.key is None:
            raise MissingKey(True)

    @staticmethod
    def fragments_from_response(response: Response) -> List[str]:
        items: List[Dict[str, Any]] = response.json().get('items') or list()
        fragments: List[str] = list()
        for item in items:
            matches = item.get("text_matches") or list()
            for match in matches:
                fragments.append(match.get("fragment"))
        return [fragment for fragment in fragments if fragment is not None]

    @staticmethod
    def page_from_response(page: str, response: Response) -> Optional[Any]:
        page_link = response.links.get(page)
        if page_link:
            parsed = urlparse.urlparse(page_link.get("url"))
            params = urlparse.parse_qs(parsed.query)
            pages: List[Any] = params.get('page', [None])
            page_number = pages[0] and int(pages[0])
            return page_number
        else:
            return None

    def handle_response(self, response: Response) -> Optional[Any]:
        if response.ok:
            results = self.fragments_from_response(response)
            next_page = self.page_from_response("next", response)
            last_page = self.page_from_response("last", response)
            return SuccessResult(results, next_page, last_page)
        elif response.status_code == 429 or response.status_code == 403:
            return RetryResult(60)
        else:
            try:
                return ErrorResult(response.status_code, response.json())
            except ValueError:
                return ErrorResult(response.status_code, response.text)

    def do_search(self, page: Optional[int]) -> Response:
        if page is None:
            url = f'https://{self.server}/search/code?q="{self.word}"'
        else:
            url = f'https://{self.server}/search/code?q="{self.word}"&page={page}'
        headers = {
            'Host': self.server,
            'User-agent': Core.get_user_agent(),
            'Accept': "application/vnd.github.v3.text-match+json",
            'Authorization': 'token {}'.format(self.key)
        }
        return requests.get(url=url, headers=headers, verify=True)

    @staticmethod
    def next_page_or_end(result: SuccessResult) -> Optional[int]:
        if result.next_page is not None:
            return result.next_page
        else:
            return result.last_page

    def process(self):
        while self.counter <= self.limit and self.page is not None:
            api_response = self.do_search(self.page)
            result = self.handle_response(api_response)
            if type(result) == SuccessResult:
                print(f'\tSearching {self.counter} results.')
                for fragment in result.fragments:
                    self.total_results += fragment
                    self.counter = self.counter + 1

                self.page = self.next_page_or_end(result)
                time.sleep(getDelay())
            elif type(result) == RetryResult:
                sleepy_time = getDelay() + result.time
                print(f'\tRetrying page in {sleepy_time} seconds...')
                time.sleep(sleepy_time)
            elif type(result) == ErrorResult:
                raise Exception(f"\tException occurred: status_code: {result.status_code} reason: {result.body}")
            else:
                raise Exception("\tUnknown exception occurred")

    def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return rawres.hostnames()
