import asyncio

import ujson
from bs4 import BeautifulSoup
from bs4.element import Tag

from theHarvester.discovery.constants import get_delay
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.parsers import myparser


class SearchSubdomainfinderc99:
    def __init__(self, word) -> None:
        self.word = word
        self.total_results: set = set()
        self.proxy = False
        # TODO add api support
        self.server = 'https://subdomainfinder.c99.nl/'
        self.totalresults = ''
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = status
        self.stop_reason = reason

    async def do_search(self) -> None:
        # Based on https://gist.github.com/th3gundy/bc83580cbe04031e9164362b33600962
        headers = {'User-Agent': Core.get_browser_user_agent()}
        async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy) as session:
            metadata = await AsyncFetcher.fetch(
                session=session,
                url=self.server,
                include_metadata=True,
            )
            if error := provider_http_error(metadata):
                self._stop(*error)
                return
            assert isinstance(metadata, FetcherResponse)
            if not isinstance(metadata.body, str):
                self._stop('failed', 'invalid-response')
                return
            data = await self.get_csrf_params(metadata.body)
            if not data:
                self._stop('failed', 'invalid-response')
                return

            data['scan_subdomains'] = ''
            data['domain'] = self.word
            data['privatequery'] = 'on'
            await asyncio.sleep(get_delay())
            second_resp = await AsyncFetcher.post_fetch(
                self.server,
                session=session,
                data=ujson.dumps(data),
                include_metadata=True,
            )
            if error := provider_http_error(second_resp):
                self._stop(*error)
                return
            assert isinstance(second_resp, FetcherResponse)
            if not isinstance(second_resp.body, str):
                self._stop('failed', 'invalid-response')
                return
            self.totalresults += second_resp.body
        self.execution_status = 'completed'
        self.stop_reason = None if await self.get_hostnames() else 'no-results'

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        try:
            await self.do_search()
        except Exception:
            self._stop('failed', 'transport-error')

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
