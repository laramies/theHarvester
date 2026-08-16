import asyncio
import json

from bs4 import BeautifulSoup
from bs4.element import Tag

from theHarvester.discovery.constants import get_delay
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser


class SearchSubdomainfinderc99:
    def __init__(self, word) -> None:
        self.word = word
        self.total_results: set = set()
        self.proxy = False
        # TODO add api support
        self.server = 'https://subdomainfinder.c99.nl/'
        self.totalresults = ''

    async def do_search(self) -> SourceExecutionReport | None:
        # Based on https://gist.github.com/th3gundy/bc83580cbe04031e9164362b33600962
        headers = {'User-Agent': Core.get_browser_user_agent()}
        async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy) as session:
            metadata = await AsyncFetcher.fetch(
                session=session,
                url=self.server,
                include_metadata=True,
            )
            if error := provider_http_error(metadata):
                return SourceExecutionReport(*error)
            assert isinstance(metadata, FetcherResponse)
            if not isinstance(metadata.body, str):
                return SourceExecutionReport('failed', 'invalid-response')
            data = await self.get_csrf_params(metadata.body)
            if not data:
                return SourceExecutionReport('failed', 'invalid-response')

            data['scan_subdomains'] = ''
            data['domain'] = self.word
            data['privatequery'] = 'on'
            await asyncio.sleep(get_delay())
            second_resp = await AsyncFetcher.post_fetch(
                self.server,
                session=session,
                data=json.dumps(data, separators=(',', ':')),
                include_metadata=True,
            )
            if error := provider_http_error(second_resp):
                return SourceExecutionReport(*error)
            assert isinstance(second_resp, FetcherResponse)
            if not isinstance(second_resp.body, str):
                return SourceExecutionReport('failed', 'invalid-response')
            self.totalresults += second_resp.body
        return None

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')

    @staticmethod
    async def get_csrf_params(data):
        csrf_params: dict[str, str] = {}
        html = BeautifulSoup(data, 'html.parser').find('div', {'class': 'input-group'})
        if not isinstance(html, Tag):
            return csrf_params
        for c in html.find_all('input'):
            try:
                if not isinstance(c, Tag):
                    continue
                name = c.get('name')
                value = c.get('value')
                if isinstance(name, str) and value is not None:
                    csrf_params[name] = str(value)
            except Exception:
                continue

        return csrf_params
