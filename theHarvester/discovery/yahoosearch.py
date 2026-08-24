from __future__ import annotations

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser


class SearchYahoo:
    def __init__(self, word, limit: int | None) -> None:
        self.word = word
        self.total_results = ''
        self.server = 'search.yahoo.com'
        self.limit = limit
        self.proxy = False

    def _page(self, response: object) -> tuple[str | None, SourceExecutionReport | None]:
        if response is None:
            return None, SourceExecutionReport('partial' if self.total_results else 'failed', 'transport-error')
        if isinstance(response, FetcherResponse):
            if not 200 <= response.status < 300:
                return None, SourceExecutionReport('partial' if self.total_results else 'failed', f'http-{response.status}')
            response = response.body
        if not isinstance(response, str):
            return None, SourceExecutionReport('partial' if self.total_results else 'failed', 'invalid-response')
        normalized = response.casefold()
        if not response.strip() or 'no results' in normalized or 'no-results' in normalized:
            return '', None
        if 'captcha' in normalized or 'verify you are human' in normalized:
            return None, SourceExecutionReport('partial' if self.total_results else 'failed', 'security-verification')
        if 'access denied' in normalized or 'temporarily blocked' in normalized:
            return None, SourceExecutionReport('partial' if self.total_results else 'failed', 'access-denied')
        return response, None

    async def do_search(self) -> SourceExecutionReport | None:
        base_url = f'https://{self.server}/search?p=%40{self.word}&b=xx&pz=10'
        headers = {'Host': self.server, 'User-Agent': Core.get_browser_user_agent()}
        if self.limit is None:
            seen_pages: set[str] = set()
            offset = 0
            while True:
                response = await AsyncFetcher.fetch(
                    url=base_url.replace('xx', str(offset)),
                    headers=headers,
                    proxy=self.proxy,
                    include_metadata=True,
                )
                body, report = self._page(response)
                if report is not None:
                    return report
                if not body:
                    return None
                if body in seen_pages:
                    return SourceExecutionReport('partial', 'repeated-page')
                seen_pages.add(body)
                self.total_results += f' {body}'
                offset += 10
        urls = [base_url.replace('xx', str(num)) for num in range(0, self.limit, 10)]
        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy, include_metadata=True)
        if urls and not responses:
            return SourceExecutionReport('failed', 'transport-error')
        seen_finite_pages: set[str] = set()
        for response in responses:
            body, report = self._page(response)
            if report is not None:
                return report
            if not body:
                break
            if body in seen_finite_pages:
                return SourceExecutionReport('partial', 'repeated-page')
            seen_finite_pages.add(body)
            self.total_results += f' {body}'
        return None

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        toparse_emails = await rawres.emails()
        emails = set()
        # strip out numbers and dashes for emails that look like xxx-xxx-xxxemail@host.tld
        for email in toparse_emails:
            email = str(email)
            if '-' in email and email[0].isdigit() and email.index('-') <= 9:
                while email[0] == '-' or email[0].isdigit():
                    email = email[1:]
            emails.add(email)
        return list(emails)

    async def get_hostnames(self, proxy: bool = False):
        self.proxy = proxy
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
