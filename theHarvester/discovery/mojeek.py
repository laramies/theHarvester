import asyncio
import logging
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, Tag

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport, SourceReportStatus
from theHarvester.parsers import myparser

logger = logging.getLogger(__name__)


def _has_result_link(entry: Tag) -> bool:
    for link in entry.find_all('a', href=True):
        href = link.get('href')
        if not isinstance(href, str):
            continue
        try:
            url = urlsplit(href)
            if url.scheme in {'http', 'https'} and url.hostname:
                return True
        except ValueError:
            continue
    return False


class SearchMojeek:
    REQUEST_DELAY_SECONDS = 2.0

    def __init__(self, word: str, limit: int | None) -> None:
        self.word = word
        self.limit = limit
        self.total_results = ''
        self.proxy = False
        self.server = 'www.mojeek.com'
        self.api_server = 'api.mojeek.com'
        self._report: SourceExecutionReport | None = None

        try:
            self.api_key = Core.mojeek_key()
        except Exception:
            self.api_key = ''

        if self.api_key:
            logger.info('[*] Mojeek: API key detected.')
        else:
            logger.info('[*] Mojeek: No API key found, using default scraping mode.')

    def _stop(self, status: SourceReportStatus, reason: str) -> None:
        self._report = SourceExecutionReport('partial' if self.total_results else status, reason)

    def _api_page_results(self, response: FetcherResponse) -> list[str] | None:
        if response.status == 403:
            self._stop('failed', 'access-denied')
            return None
        if response.status == 429:
            self._stop('rate-limited', 'http-429')
            return None
        if not 200 <= response.status < 300:
            self._stop('failed', f'http-{response.status}')
            return None
        data = response.body.get('response', response.body) if isinstance(response.body, dict) else None
        if not isinstance(data, dict):
            self._stop('failed', 'invalid-response')
            return None
        status = data.get('status')
        if isinstance(status, str) and 'speed limit reached' in status.casefold():
            self._stop('rate-limited', 'speed-limit-reached')
            return None
        if isinstance(status, str) and 'denied' in status.casefold():
            self._stop('failed', 'access-denied')
            return None
        if 'status' in data and not isinstance(status, str):
            self._stop('failed', 'invalid-response')
            return None
        results = data.get('results')
        if not isinstance(results, list):
            self._stop('failed', 'invalid-response')
            return None
        parsed_results: list[str] = []
        for result in results:
            if not isinstance(result, dict):
                self._stop('failed', 'invalid-response')
                return None
            url_value = result.get('url')
            title_value = result.get('title')
            description_value = result.get('desc')
            url = url_value.replace('\\/', '/') if isinstance(url_value, str) else ''
            title = title_value if isinstance(title_value, str) else ''
            description = description_value if isinstance(description_value, str) else ''
            if not any((url, title, description)):
                self._stop('failed', 'invalid-response')
                return None
            parsed_results.append(f'{url} {title} {description}')
        return parsed_results

    async def _search_api(self, headers: dict[str, str], session) -> None:
        if self.limit is None:
            seen_pages: set[tuple[str, ...]] = set()
            offset = 1
            while True:
                if offset > 1:
                    await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
                url = f'https://{self.api_server}/search?api_key={self.api_key}&q={self.word}&fmt=json&s={offset}'
                responses = await AsyncFetcher.fetch_all(
                    [url], headers=headers, session=session, json=True, include_metadata=True
                )
                if len(responses) != 1 or not isinstance(responses[0], FetcherResponse):
                    self._stop('failed', 'transport-error')
                    return
                parsed_results = self._api_page_results(responses[0])
                if parsed_results is None:
                    return
                if not parsed_results:
                    return
                signature = tuple(parsed_results)
                if signature in seen_pages:
                    self._stop('partial', 'repeated-page')
                    return
                seen_pages.add(signature)
                self.total_results += f' {" ".join(parsed_results)} '
                offset += 10

        result_limit = self.limit
        seen_finite_pages: set[tuple[str, ...]] = set()
        offset = 1
        while offset <= result_limit:
            if offset > 1:
                await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
            url = f'https://{self.api_server}/search?api_key={self.api_key}&q={self.word}&fmt=json&s={offset}'
            responses = await AsyncFetcher.fetch_all([url], headers=headers, session=session, json=True, include_metadata=True)
            if len(responses) != 1 or not isinstance(responses[0], FetcherResponse):
                self._stop('failed', 'transport-error')
                return
            parsed_results = self._api_page_results(responses[0])
            if parsed_results is None:
                return
            if not parsed_results:
                break
            signature = tuple(parsed_results)
            if signature in seen_finite_pages:
                self._stop('partial', 'repeated-page')
                return
            seen_finite_pages.add(signature)
            self.total_results += f' {" ".join(parsed_results)} '
            offset += 10
        logger.info('[*] Mojeek: API search completed successfully.')

    async def _search_keyless(self, headers: dict[str, str], session) -> None:
        seen_bodies: set[str] = set()
        offset = 0
        page = 0
        while self.limit is None or offset < self.limit:
            url = f'https://{self.server}/search?q={self.word}&s={offset}'
            if page:
                await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
            response = await AsyncFetcher.fetch(
                session=session,
                url=url,
                headers=headers,
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
            document = BeautifulSoup(response.body, 'html.parser')
            for element in document.select('script, style'):
                element.decompose()
            result_blocks = document.select('.results-standard')
            has_result_content = any(block.get_text(strip=True) or block.find('a', href=True) for block in result_blocks)
            result_entries: list[str] = []
            for block in result_blocks:
                for entry in block.find_all('li'):
                    if _has_result_link(entry):
                        result_entries.append(str(entry))
                        entry.extract()
            # Exclude linked snippets, not containers that may hold provider messages.
            normalized_body = ' '.join(document.get_text(' ', strip=True).split()).casefold()
            failure: tuple[SourceReportStatus, str] | None = None
            if 'speed limit reached' in normalized_body:
                failure = ('rate-limited', 'speed-limit-reached')
            elif any(marker in normalized_body for marker in ('captcha', 'verify you are human', 'prove you are human')):
                failure = ('failed', 'security-verification')
            elif 'access denied' in normalized_body or 'temporarily blocked' in normalized_body:
                failure = ('failed', 'access-denied')
            if failure or 'no results' in normalized_body or document.select_one('.no-results') is not None:
                self.total_results += ' '.join(result_entries)
                if failure:
                    self._stop(*failure)
                return
            if not result_blocks:
                self._stop('failed', 'invalid-response')
                return
            if not has_result_content:
                return
            if response.body in seen_bodies:
                self._stop('partial', 'repeated-page')
                return
            seen_bodies.add(response.body)
            self.total_results += f' {response.body}'
            offset += 10
            page += 1

    async def do_search(self, session) -> SourceExecutionReport | None:
        self._report = None
        user_agent = Core.get_user_agent() if self.api_key else Core.get_browser_user_agent()
        headers = {'User-Agent': user_agent}
        if self.api_key:
            await self._search_api(headers, session)
        else:
            await self._search_keyless(headers, session)
        return self._report

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        async with AsyncFetcher.open_session(proxy=self.proxy, request_timeout=60) as session:
            return await self.do_search(session)

    async def get_emails(self) -> list[str]:
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self) -> list[str]:
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
