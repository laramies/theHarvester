import json
import math
from json.decoder import JSONDecodeError

from theHarvester.lib.core import *
from theHarvester.parsers import myparser


class SearchQwant:
    def __init__(self, word, start, limit) -> None:
        self.word = word
        self.total_results = ""
        self.limit = int(limit)
        self.start = int(start)
        self.proxy = False

    def get_start_offset(self) -> int:
        """
        print(get_start_offset(0))
        >>> 0
        print(get_start_offset(7))
        >>> 0
        print(get_start_offset(25))
        >>> 20
        print(get_start_offset(42))
        >>> 40
        """
        start = int(math.floor(self.start / 10.0)) * 10
        return max(start, 0)

    async def do_search(self) -> None:
        headers = {'User-agent': Core.get_user_agent()}

        start = self.get_start_offset()
        limit = self.limit + start
        step = 10

        api_urls = [
            f"https://api.qwant.com/api/search/web?count=10&offset={str(offset)}&q={self.word}&t=web&r=US&device=desktop&safesearch=0&locale=en_US&uiv=4"
            for offset in range(start, limit, step)
        ]

        responses = await AsyncFetcher.fetch_all(api_urls, headers=headers, proxy=self.proxy)

        for response in responses:
            try:
                json_response = json.loads(response)
            except JSONDecodeError:
                # sometimes error 502 from server
                continue

            try:
                response_items = json_response['data']['result']['items']
            except KeyError:
                if json_response.get("status", None) \
                        and json_response.get("error", None) == 24:
                    # https://www.qwant.com/anti_robot
                    print("Rate limit reached - IP Blocked until captcha is solved")
                    break
                continue

            for response_item in response_items:
                desc = response_item.get('desc', '')
                """
                response_item[0]['desc'] = "end of previous description."
                response_item[1]['desc'] = "john.doo@company.com start the next description"
                total_results = "end of first description.john.doo@company.com"
                get_emails() = "description.john.doo@company.com"
                """
                self.total_results += " "
                self.total_results += desc

    async def get_emails(self) -> set:
        parser = myparser.Parser(self.total_results, self.word)
        return await parser.emails()

    async def get_hostnames(self) -> list:
        parser = myparser.Parser(self.total_results, self.word)
        return await parser.hostnames()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
