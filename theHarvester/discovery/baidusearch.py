from __future__ import annotations

import asyncio
import importlib
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ProxyUnavailableError
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Collection
    from types import ModuleType

playwright_api: ModuleType | None
try:
    playwright_api = importlib.import_module('playwright.async_api')
except ImportError:
    playwright_api = None


class SearchBaidu:
    REQUEST_DELAY_SECONDS = 1.0

    @staticmethod
    async def _close(close: Callable[[], Awaitable[None]]) -> BaseException | None:
        try:
            await close()
        except BaseException as error:
            return error
        return None

    @staticmethod
    def _cleanup_failure(primary: BaseException | None, cleanup_errors: Collection[BaseException]) -> BaseException | None:
        if isinstance(primary, asyncio.CancelledError):
            return primary
        cancellation = next((error for error in cleanup_errors if isinstance(error, asyncio.CancelledError)), None)
        return cancellation or primary or next(iter(cleanup_errors), None)

    @staticmethod
    def _response_report(status: int, body: str, redirect: str = '') -> SourceExecutionReport | None:
        if status == 429:
            return SourceExecutionReport('rate-limited', 'http-429')
        if '百度安全验证' in body or 'wappass.baidu.com/static/captcha' in f'{redirect} {body}':
            return SourceExecutionReport('failed', 'security-verification')
        if status >= 300:
            return SourceExecutionReport('failed', f'http-{status}')
        if not body:
            return SourceExecutionReport('failed', 'no-response')
        return None

    async def _http_search(self, urls, proxy: str | bool) -> SourceExecutionReport | None:
        headers = {'Host': self.server, 'User-Agent': Core.get_browser_user_agent()}
        seen_bodies: set[str] = set()
        try:
            async with AsyncFetcher.open_session(headers=headers, proxy=proxy, request_timeout=60) as session:
                for page_number, url in enumerate(urls):
                    if page_number:
                        await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
                    response = await AsyncFetcher.fetch(
                        session=session,
                        url=url,
                        follow_redirects=False,
                        include_metadata=True,
                    )
                    if not isinstance(response, FetcherResponse):
                        return SourceExecutionReport('partial' if self.total_results else 'failed', 'transport-error')
                    if not isinstance(response.body, str):
                        return SourceExecutionReport('partial' if self.total_results else 'failed', 'invalid-response')
                    body = response.body
                    if report := self._response_report(response.status, body, response.headers.get('location', '')):
                        return SourceExecutionReport('partial', report.stop_reason) if self.total_results else report
                    if body in seen_bodies:
                        return SourceExecutionReport('partial', 'repeated-page')
                    seen_bodies.add(body)
                    self.total_results += f' {body}'
        except asyncio.CancelledError:
            raise
        except ProxyUnavailableError:
            return SourceExecutionReport('partial' if self.total_results else 'failed', 'proxy-unavailable')
        except Exception:
            return SourceExecutionReport('partial' if self.total_results else 'failed', 'transport-error')
        return None

    def __init__(self, word, limit: int | None) -> None:
        self.word = word
        self.total_results = ''
        self.server = 'www.baidu.com'
        self.limit = limit
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
        base_url = f'https://{self.server}/s'

        def urls():
            offset = 0
            while self.limit is None or offset < self.limit:
                params: dict[str, str | int] = {
                    'ie': 'utf-8',
                    'f': 8,
                    'tn': 'baidu',
                    'wd': f'site:{self.word}',
                    'rqlang': 'en',
                    'rsv_enter': 1,
                    'rsv_dl': 'tb_enter',
                }
                if offset:
                    params['pn'] = offset
                yield f'{base_url}?{urlencode(params)}'
                offset += 10

        page_urls = urls()
        if playwright_api is None:
            return await self._http_search(page_urls, self.proxy)

        proxy_url, _proxy_type = AsyncFetcher._resolve_proxy(self.proxy)
        manager = playwright_api.async_playwright()
        manager_entered = False
        browser = context = page = None
        report = None
        primary_error: BaseException | None = None
        cleanup_errors: list[BaseException] = []
        seen_bodies: set[str] = set()
        try:
            playwright = await manager.__aenter__()
            manager_entered = True
            browser = await playwright.chromium.launch(
                headless=True,
                proxy={'server': proxy_url} if proxy_url else None,
            )
            context = await browser.new_context(user_agent=Core.get_browser_user_agent())
            page = await context.new_page()
            for page_number, url in enumerate(page_urls):
                if page_number:
                    await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
                response = await page.goto(url, wait_until='domcontentloaded', timeout=60_000)
                if response is None:
                    report = SourceExecutionReport('partial' if self.total_results else 'failed', 'transport-error')
                    break
                body = await page.content()
                if response_report := self._response_report(response.status, body, page.url):
                    report = (
                        SourceExecutionReport('partial', response_report.stop_reason) if self.total_results else response_report
                    )
                    break
                if body in seen_bodies:
                    report = SourceExecutionReport('partial', 'repeated-page')
                    break
                seen_bodies.add(body)
                self.total_results += f' {body}'
        except BaseException as error:
            primary_error = error
        finally:
            for close in (
                page.close if page is not None else None,
                context.close if context is not None else None,
                browser.close if browser is not None else None,
            ):
                if close is not None and (close_error := await self._close(close)):
                    cleanup_errors.append(close_error)
            if manager_entered:
                exit_error = self._cleanup_failure(primary_error, cleanup_errors)
                try:
                    await manager.__aexit__(
                        type(exit_error) if exit_error is not None else None,
                        exit_error,
                        exit_error.__traceback__ if exit_error is not None else None,
                    )
                except BaseException as error:
                    cleanup_errors.append(error)

        final_error = self._cleanup_failure(primary_error, cleanup_errors)
        if isinstance(final_error, playwright_api.Error) or (
            isinstance(final_error, ValueError) and str(final_error) == 'startupinfo is not supported'
        ):
            if not self.total_results:
                return await self._http_search(urls(), proxy_url or False)
            return SourceExecutionReport('partial', 'transport-error')
        if final_error is not None:
            raise final_error
        if report is not None and report.stop_reason == 'transport-error' and not self.total_results:
            return await self._http_search(urls(), proxy_url or False)
        return report

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()
        except ProxyUnavailableError:
            return SourceExecutionReport('failed', 'proxy-unavailable')

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
