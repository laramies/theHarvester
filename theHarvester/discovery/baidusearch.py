from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from theHarvester.lib.core import AsyncFetcher
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Collection


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

    def __init__(self, word, limit) -> None:
        self.word = word
        self.total_results = ''
        self.server = 'www.baidu.com'
        self.limit = limit
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
        base_url = f'https://{self.server}/s'
        urls = []
        for offset in range(0, self.limit, 10):
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
            urls.append(f'{base_url}?{urlencode(params)}')

        proxy_url, _proxy_type = AsyncFetcher._resolve_proxy(self.proxy)
        manager = async_playwright()
        manager_entered = False
        browser = context = page = None
        report = None
        primary_error: BaseException | None = None
        cleanup_errors: list[BaseException] = []
        try:
            playwright = await manager.__aenter__()
            manager_entered = True
            browser = await playwright.chromium.launch(
                headless=True,
                proxy={'server': proxy_url} if proxy_url else None,
            )
            context = await browser.new_context()
            page = await context.new_page()
            for page_number, url in enumerate(urls):
                if page_number:
                    await asyncio.sleep(self.REQUEST_DELAY_SECONDS)
                response = await page.goto(url, wait_until='domcontentloaded', timeout=60_000)
                if response is None:
                    report = SourceExecutionReport('failed', 'transport-error')
                    break
                body = await page.content()
                if response.status == 429:
                    report = SourceExecutionReport('rate-limited', 'http-429')
                    break
                if '百度安全验证' in body or 'wappass.baidu.com/static/captcha' in page.url:
                    report = SourceExecutionReport('failed', 'security-verification')
                    break
                if response.status >= 300:
                    report = SourceExecutionReport('failed', f'http-{response.status}')
                    break
                if not body:
                    report = SourceExecutionReport('failed', 'no-response')
                    break
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
        if isinstance(final_error, PlaywrightError):
            return SourceExecutionReport('failed', 'transport-error')
        if final_error is not None:
            raise final_error
        return report

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
