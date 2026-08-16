import asyncio
from urllib.parse import urlencode

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser


class SearchBaidu:
    REQUEST_DELAY_SECONDS = 1.0

    def __init__(self, word, limit) -> None:
        self.word = word
        self.total_results = ''
        self.server = 'www.baidu.com'
        self.hostname = 'www.baidu.com'
        self.limit = limit
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
        headers = {'Host': self.hostname, 'User-Agent': Core.get_browser_user_agent()}
        base_url = f'https://{self.server}/s'
        urls = [
            f'{base_url}?{urlencode({"wd": f"site:{self.word}", "pn": num})}'
            for num in range(0, self.limit, 10)
            if num <= self.limit
        ]
        proxy_url, proxy_type = AsyncFetcher._resolve_proxy(self.proxy)
        session = await AsyncFetcher._build_session(
            headers,
            AsyncFetcher._request_timeout(60),
            proxy_url,
            proxy_type,
            AsyncFetcher._ssl_context(),
        )
        try:
            homepage_url = f'https://{self.server}/'
            for url in [homepage_url, *urls]:
                if url != homepage_url:
                    await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
                response = await AsyncFetcher.fetch(
                    session=session,
                    url=url,
                    proxy=proxy_url or False,
                    follow_redirects=False,
                    include_metadata=True,
                )
                if not isinstance(response, FetcherResponse):
                    return SourceExecutionReport('failed', 'transport-error')

                location = response.headers.get('location', '')
                body = response.body if isinstance(response.body, str) else ''
                if response.status == 429:
                    return SourceExecutionReport('rate-limited', 'http-429')
                if '百度安全验证' in body or 'wappass.baidu.com/static/captcha' in f'{location} {body}':
                    return SourceExecutionReport('failed', 'security-verification')
                if response.status >= 300:
                    return SourceExecutionReport('failed', f'http-{response.status}')
                if not body:
                    return SourceExecutionReport('failed', 'no-response')
                if url != homepage_url:
                    self.total_results += f' {body}'
        finally:
            await session.close()
        return None

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
