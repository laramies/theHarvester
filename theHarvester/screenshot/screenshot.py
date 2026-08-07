"""Screenshot module that utilizes playwright to asynchronously
take screenshots
"""

import logging
import os
import ssl
import sys
from collections.abc import Collection
from datetime import datetime
from urllib.parse import urlsplit

import aiohttp
import certifi
from playwright.async_api import async_playwright

from theHarvester.lib.public_egress import PublicResolver

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
            if proxy:
                logger.info('Refusing screenshot proxy that cannot pin the validated target address')
                return '', ''
            timeout = aiohttp.ClientTimeout(total=35)
            urls = (url,) if url.startswith(('http://', 'https://')) else (f'https://{url}', f'http://{url}')
            resolver = PublicResolver()
            for candidate in urls:
                parsed = urlsplit(candidate)
                if parsed.hostname is None:
                    return '', ''
                await resolver.resolve(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
            sslcontext = ssl.create_default_context(cafile=certifi.where())
            connector = aiohttp.TCPConnector(ssl=sslcontext, resolver=resolver)

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                for candidate in urls:
                    try:
                        async with session.get(candidate, allow_redirects=False) as resp:
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
        parsed = urlsplit(url)
        if parsed.hostname is None:
            return ''
        resolver = PublicResolver()
        try:
            addresses = await resolver.resolve(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
        except OSError as error:
            logger.info(f'Refusing screenshot target {url}: {error}')
            return ''
        logger.info(f'Attempting to take a screenshot of: {url}')
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[f'--host-resolver-rules=MAP {parsed.hostname} {addresses[0]["host"]}'],
            )
            # New browser context
            context = await browser.new_context()

            async def guard_request(route) -> None:
                request_url = urlsplit(route.request.url)
                if request_url.scheme in {'http', 'https'} and request_url.hostname != parsed.hostname:
                    await route.abort('blockedbyclient')
                else:
                    await route.continue_()

            async def block_web_socket(web_socket) -> None:
                await web_socket.close(code=1008, reason='Wayfinder blocks WebSocket egress')

            await context.route('**/*', guard_request)
            await context.route_web_socket('**/*', block_web_socket)
            page = await context.new_page()
            path = rf'{self.output}{self.slash}{url.replace("http://", "").replace("https://", "")}.png'
            date = str(datetime.now())
            try:
                # Will fail if network idle or load event doesn't fire after
                # 35s which should be handled
                await page.goto(url, timeout=35000)
                await page.screenshot(path=path)
                os.chmod(path, 0o600)
            except Exception as e:
                logger.info(f'An exception has occurred attempting to screenshot: {url} : {e}')
                path = ''
            finally:
                await page.close()
                await context.close()
                await browser.close()
                logger.info(f'{date} {url} {path}')
        return url if path else ''
