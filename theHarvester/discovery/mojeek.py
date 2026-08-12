import asyncio
import logging

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.parsers import myparser

logger = logging.getLogger(__name__)


class SearchMojeek:
    REQUEST_DELAY_SECONDS = 1.0

    def __init__(self, word, limit) -> None:
        self.word = word
        self.limit = limit
        self.total_results = ''
        self.proxy = False
        self.server = 'www.mojeek.com'
        self.api_server = 'api.mojeek.com'
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

        try:
            self.api_key = Core.mojeek_key()
        except Exception:
            self.api_key = ''

        if self.api_key:
            logger.info('[*] Mojeek: API key detected.')
        else:
            logger.info('[*] Mojeek: No API key found, using default scraping mode.')

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self.total_results else status
        self.stop_reason = reason

    async def _search_api(self, headers: dict[str, str]) -> None:
        urls = [
            f'https://{self.api_server}/search?api_key={self.api_key}&q={self.word}&fmt=json&s={num}'
            for num in range(1, self.limit, 10)
        ]
        responses = await AsyncFetcher.fetch_all(
            urls,
            headers=headers,
            proxy=self.proxy,
            json=True,
            include_metadata=True,
        )
        for response in responses:
            if not isinstance(response, FetcherResponse):
                self._stop('failed', 'transport-error')
                return
            if response.status == 403:
                self._stop('failed', 'access-denied')
                return
            if response.status == 429:
                self._stop('rate-limited', 'http-429')
                return
            if not 200 <= response.status < 300:
                self._stop('failed', f'http-{response.status}')
                return

            data = response.body.get('response', response.body) if isinstance(response.body, dict) else None
            if not isinstance(data, dict):
                self._stop('failed', 'invalid-response')
                return
            status = data.get('status')
            if isinstance(status, str) and 'denied' in status.casefold():
                self._stop('failed', 'access-denied')
                return
            if 'status' in data and not isinstance(status, str):
                self._stop('failed', 'invalid-response')
                return
            results = data.get('results')
            if not isinstance(results, list):
                self._stop('failed', 'invalid-response')
                return
            for result in results:
                if not isinstance(result, dict):
                    self._stop('failed', 'invalid-response')
                    return
                url_value = result.get('url')
                title_value = result.get('title')
                description_value = result.get('desc')
                url = url_value.replace('\\/', '/') if isinstance(url_value, str) else ''
                title = title_value if isinstance(title_value, str) else ''
                description = description_value if isinstance(description_value, str) else ''
                if not any((url, title, description)):
                    self._stop('failed', 'invalid-response')
                    return
                self.total_results += f' {url} {title} {description} '

        self.execution_status = 'completed'
        self.stop_reason = None if self.total_results else 'no-results'
        logger.info('[*] Mojeek: API search completed successfully.')

    async def _search_keyless(self, headers: dict[str, str]) -> None:
        urls = [f'https://{self.server}/search?q={self.word}&s={num}' for num in range(0, self.limit, 10)]
        for page, url in enumerate(urls):
            if page:
                await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
            response = await AsyncFetcher.fetch(
                url=url,
                headers=headers,
                proxy=self.proxy,
                request_timeout=60,
                follow_redirects=False,
                include_metadata=True,
            )
            if not isinstance(response, FetcherResponse):
                self._stop('failed', 'transport-error')
                return
            if response.status == 403:
                self._stop('failed', 'access-denied')
                return
            if response.status == 429:
                self._stop('rate-limited', 'http-429')
                return
            if not 200 <= response.status < 300:
                self._stop('failed', f'http-{response.status}')
                return
            if not isinstance(response.body, str) or not response.body.strip():
                self._stop('failed', 'invalid-response')
                return
            normalized_body = response.body.casefold()
            if any(marker in normalized_body for marker in ('captcha', 'verify you are human', 'prove you are human')):
                self._stop('failed', 'security-verification')
                return
            if 'access denied' in normalized_body or 'temporarily blocked' in normalized_body:
                self._stop('failed', 'access-denied')
                return
            if 'no results' in normalized_body or 'no-results' in normalized_body:
                self.execution_status = 'completed'
                self.stop_reason = 'no-results'
                return
            if 'results-standard' not in normalized_body:
                self._stop('failed', 'invalid-response')
                return
            self.total_results += f' {response.body}'

        self.execution_status = 'completed'

    async def do_search(self) -> None:
        self.execution_status = None
        self.stop_reason = None
        user_agent = Core.get_user_agent() if self.api_key else Core.get_browser_user_agent()
        headers = {'User-Agent': user_agent}
        if self.api_key:
            await self._search_api(headers)
        else:
            await self._search_keyless(headers)

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
