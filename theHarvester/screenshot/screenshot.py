"""Screenshot module that utilizes playwright to asynchronously
take screenshots
"""

import logging
import os
import ssl
import sys
from collections.abc import Collection
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
import certifi
from aiohttp_socks import ProxyConnector
from playwright.async_api import async_playwright

logger = logging.getLogger(__name__)


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
    async def verify_installation() -> None:
        # Helper function that verifies playwright & chromium is installed
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                await browser.close()
            logger.info('Playwright and Chromium are successfully installed.')
        except Exception as e:
            logger.info(f'An exception has occurred while attempting to verify installation: {e}')

    @staticmethod
    def chunk_list(items: Collection, chunk_size: int) -> list:
        # Based off of: https://github.com/apache/incubator-sdap-ingester
        return [list(items)[i : i + chunk_size] for i in range(0, len(items), chunk_size)]

    @staticmethod
    async def visit(url: str, proxy: str | None = None) -> tuple[str, str]:
        try:
            timeout = aiohttp.ClientTimeout(total=35)
            urls = (url,) if url.startswith(('http://', 'https://')) else (f'https://{url}', f'http://{url}')
            sslcontext = ssl.create_default_context(cafile=certifi.where())
            connector: ProxyConnector | aiohttp.TCPConnector
            proxy_param = None
            if proxy and proxy.startswith('socks5://'):
                connector = ProxyConnector.from_url(proxy, ssl=sslcontext)
            else:
                connector = aiohttp.TCPConnector(ssl=sslcontext)
                proxy_param = proxy

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                for candidate in urls:
                    try:
                        async with session.get(candidate, proxy=proxy_param) as resp:
                            text = await resp.text('UTF-8')
                            return str(resp.url), text
                    except (aiohttp.ClientError, TimeoutError) as e:
                        logger.info(f'An exception has occurred while attempting to visit {candidate} : {e}')
            return '', ''
        except Exception as e:
            logger.info(f'An exception has occurred while attempting to visit {url} : {e}')
            return '', ''

    async def take_screenshot(self, url: str) -> str:
        url = f'https://{url}' if not url.startswith(('http://', 'https://')) else url
        logger.info(f'Attempting to take a screenshot of: {url}')
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            # New browser context
            context = await browser.new_context()
            page = await context.new_page()
            path: Path | None = self.screenshot_path(url)
            date = str(datetime.now())
            try:
                # Will fail if network idle or load event doesn't fire after
                # 35s which should be handled
                await page.goto(url, timeout=35000)
                await page.screenshot(path=path)
                if path is not None:
                    os.chmod(path, 0o600)
            except Exception as e:
                logger.info(f'An exception has occurred attempting to screenshot: {url} : {e}')
                path = None
            finally:
                await page.close()
                await context.close()
                await browser.close()
                logger.info(f'{date} {url} {path}')
        return url if path else ''

    def screenshot_path(self, url: str) -> Path:
        parsed = urlsplit(url if url.startswith(('http://', 'https://')) else f'https://{url}')
        hostname = (parsed.hostname or 'unknown-host').replace(':', '_')
        port = f'_{parsed.port}' if parsed.port else ''
        return Path(self.output) / f'{hostname}{port}.png'
