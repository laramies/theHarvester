"""Screenshot module that utilizes playwright to asynchronously
take screenshots
"""

import asyncio
import logging
import os
import ssl
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Collection
from contextlib import asynccontextmanager
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
import certifi
from aiohttp_socks import ProxyConnector
from playwright.async_api import Browser, async_playwright

logger = logging.getLogger(__name__)

REACHABILITY_LIMIT = 20
CAPTURE_LIMIT = 3


def _target_url(value: str, scheme: str = 'https') -> str:
    if value.startswith(('http://', 'https://')):
        return value
    try:
        address = ip_address(value)
    except ValueError:
        host = value
    else:
        host = f'[{address}]' if address.version == 6 else str(address)
    return f'{scheme}://{host}'


class ScreenShotter:
    def __init__(self, output) -> None:
        self.output = output
        self.slash = '\\' if sys.platform.startswith('win') else '/'
        self.slash = '' if (self.output[-1] == '\\' or self.output[-1] == '/') else self.slash

    def verify_path(self) -> bool:
        try:
            if not os.path.isdir(self.output):
                answer = input('[+] The output path you have entered does not exist would you like to create it (y/n): ')
                if answer.lower() == 'yes' or answer.lower() == 'y':
                    os.makedirs(self.output, mode=0o700)
                    return True
                else:
                    return False
            return True
        except Exception as e:
            logger.info(f"An exception has occurred while attempting to verify output path's existence: {e}")
            return False

    @staticmethod
    async def _visit(
        session: aiohttp.ClientSession,
        url: str,
        proxy: str | None = None,
    ) -> tuple[str, str]:
        urls = (url,) if url.startswith(('http://', 'https://')) else (_target_url(url), _target_url(url, 'http'))
        for candidate in urls:
            try:
                async with session.get(candidate, proxy=proxy) as response:
                    if response.status < 400:
                        return str(response.url), 'reachable'
            except (aiohttp.ClientError, TimeoutError) as e:
                logger.info(f'An exception has occurred while attempting to visit {candidate} : {e}')
        return '', ''

    @staticmethod
    def _connector(proxy: str | None) -> tuple[ProxyConnector | aiohttp.TCPConnector, str | None]:
        sslcontext = ssl.create_default_context(cafile=certifi.where())
        if proxy and proxy.startswith('socks5://'):
            return ProxyConnector.from_url(proxy, ssl=sslcontext), None
        return aiohttp.TCPConnector(ssl=sslcontext), proxy

    @classmethod
    async def visit(cls, url: str, proxy: str | None = None) -> tuple[str, str]:
        try:
            timeout = aiohttp.ClientTimeout(total=35)
            connector, proxy_param = cls._connector(proxy)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                return await cls._visit(session, url, proxy_param)
        except Exception as e:
            logger.info(f'An exception has occurred while attempting to visit {url} : {e}')
            return '', ''

    async def reachable_targets(
        self,
        targets: Collection[str],
        proxy: str | None = None,
    ) -> list[tuple[str, str]]:
        indexed_targets = list(enumerate(targets))
        if not indexed_targets:
            return []
        target_iterator = iter(indexed_targets)
        reachable: dict[int, tuple[str, str]] = {}
        timeout = aiohttp.ClientTimeout(total=35)
        connector, proxy_param = self._connector(proxy)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:

            async def worker() -> None:
                while True:
                    try:
                        index, target = next(target_iterator)
                    except StopIteration:
                        return
                    final_url, status = await self._visit(session, target, proxy_param)
                    if status:
                        reachable[index] = (target, final_url)

            tasks = [
                asyncio.create_task(worker(), name=f'screenshot-reachability-{index}')
                for index in range(min(REACHABILITY_LIMIT, len(indexed_targets)))
            ]
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        return [reachable[index] for index in sorted(reachable)]

    @staticmethod
    async def _close(resource: object, resource_name: str) -> BaseException | None:
        try:
            await resource.close()  # type: ignore[attr-defined]
        except BaseException as error:
            logger.info(f'An exception occurred while closing screenshot {resource_name}: {error}')
            return error
        return None

    @staticmethod
    def _cleanup_failure(
        primary: BaseException | None,
        cleanup_errors: Collection[BaseException],
    ) -> BaseException | None:
        if isinstance(primary, asyncio.CancelledError):
            return primary
        cancellation = next((error for error in cleanup_errors if isinstance(error, asyncio.CancelledError)), None)
        return cancellation or primary or next(iter(cleanup_errors), None)

    @asynccontextmanager
    async def _browser(self) -> AsyncIterator[Browser]:
        manager = async_playwright()
        browser = None
        manager_entered = False
        primary_error: BaseException | None = None
        cleanup_errors: list[BaseException] = []
        try:
            playwright = await manager.__aenter__()
            manager_entered = True
            browser = await playwright.chromium.launch(headless=True)
            yield browser
        except BaseException as error:
            primary_error = error
        finally:
            if browser is not None:
                if close_error := await self._close(browser, 'browser'):
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
                    logger.info(f'An exception occurred while closing screenshot Playwright: {error}')
                    cleanup_errors.append(error)
        if final_error := self._cleanup_failure(primary_error, cleanup_errors):
            raise final_error

    async def _capture(self, browser: Browser, url: str, output_path: Path) -> str:
        normalized_url = _target_url(url)
        logger.info(f'Attempting to take a screenshot of: {normalized_url}')
        context = None
        page = None
        captured_url = ''
        primary_error: BaseException | None = None
        operation_error: Exception | None = None
        cleanup_errors: list[BaseException] = []
        date = str(datetime.now())
        try:
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(normalized_url, timeout=35000)
            await page.screenshot(path=output_path)
            os.chmod(output_path, 0o600)
            captured_url = normalized_url
        except Exception as error:
            operation_error = error
            logger.info(f'An exception has occurred attempting to screenshot: {normalized_url} : {error}')
        except BaseException as error:
            primary_error = error
        finally:
            if page is not None:
                if close_error := await self._close(page, 'page'):
                    cleanup_errors.append(close_error)
            if context is not None:
                if close_error := await self._close(context, 'context'):
                    cleanup_errors.append(close_error)
            logger.info(f'{date} {normalized_url} {output_path if captured_url else None}')
        if final_error := self._cleanup_failure(primary_error, cleanup_errors):
            raise final_error
        if operation_error is not None:
            return ''
        return captured_url

    async def capture_targets(
        self,
        targets: Collection[tuple[str, str]],
        record: Callable[[str, str, Path], Awaitable[None]],
    ) -> None:
        target_iterator = iter(targets)
        if not targets:
            return

        async with self._browser() as browser:

            async def worker(worker_index: int) -> None:
                async def record_capture(subject: str, captured_url: str, output_path: Path) -> None:
                    await record(subject, captured_url, output_path)

                while True:
                    try:
                        subject, url = next(target_iterator)
                    except StopIteration:
                        return
                    output_path = self.screenshot_path(subject)
                    captured_url = await self._capture(browser, url, output_path)
                    record_task: asyncio.Task[None] = asyncio.create_task(
                        record_capture(subject, captured_url, output_path),
                        name=f'screenshot-record-{worker_index}',
                    )
                    try:
                        await asyncio.shield(record_task)
                    except asyncio.CancelledError as cancellation:
                        try:
                            while not record_task.done():
                                try:
                                    await asyncio.shield(record_task)
                                except asyncio.CancelledError:
                                    continue
                            record_task.result()
                        except BaseException as error:
                            logger.info(f'An exception occurred while finishing screenshot artifact recording: {error}')
                        raise cancellation

            tasks = [
                asyncio.create_task(worker(index), name=f'screenshot-capture-{index}')
                for index in range(min(CAPTURE_LIMIT, len(targets)))
            ]
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    async def take_screenshot(self, url: str, *, output_path: Path | None = None) -> str:
        normalized_url = _target_url(url)
        path = output_path or self.screenshot_path(normalized_url)
        async with self._browser() as browser:
            return await self._capture(browser, normalized_url, path)

    def screenshot_path(self, url: str) -> Path:
        parsed = urlsplit(_target_url(url))
        hostname = (parsed.hostname or 'unknown-host').replace(':', '_')
        port = f'_{parsed.port}' if parsed.port else ''
        return Path(self.output) / f'{hostname}{port}.png'
