from urllib.parse import urlencode

from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser


class SearchBaidu:
    def __init__(self, word, limit) -> None:
        self.word = word
        self.total_results = ''
        self.server = 'www.baidu.com'
        self.hostname = 'www.baidu.com'
        self.limit = limit
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    async def do_search(self) -> None:
        self.execution_status = None
        self.stop_reason = None
        headers = {'Host': self.hostname, 'User-agent': Core.get_user_agent()}
        base_url = f'https://{self.server}/s'
        urls = [
            f'{base_url}?{urlencode({"wd": f"site:{self.word}", "pn": num})}'
            for num in range(0, self.limit, 10)
            if num <= self.limit
        ]
        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
        if not responses or all(not response for response in responses):
            self.execution_status = 'failed'
            self.stop_reason = 'no-response'
            return
        for response in responses:
            if not response:
                continue
            if '百度安全验证' in response or 'wappass.baidu.com/static/captcha' in response:
                self.execution_status = 'partial' if self.total_results else 'rate-limited'
                self.stop_reason = 'security-verification'
                return
            self.total_results += f' {response}'

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
