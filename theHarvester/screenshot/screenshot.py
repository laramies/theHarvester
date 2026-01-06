"""
Screenshot module that utilizes playwright to asynchronously
take screenshots
"""

import os
import ssl
import sys
from collections.abc import Collection
from datetime import datetime

import aiohttp
import certifi
from aiohttp_socks import ProxyConnector
from playwright.async_api import async_playwright


class ScreenShotter:
    def __init__(self, output) -> None:
        self.output = output
        self.slash = '\\' if 'win' in sys.platform else '/'
        self.slash = '' if (self.output[-1] == '\\' or self.output[-1] == '/') else self.slash

    def verify_path(self) -> bool:
        try:
            if not os.path.isdir(self.output):
                answer = input('[+] The output path you have entered does not exist would you like to create it (y/n): ')
                if answer.lower() == 'yes' or answer.lower() == 'y':
                    os.makedirs(self.output)
                    return True
                else:
                    return False
            return True
        except Exception as e:
            print(f"An exception has occurred while attempting to verify output path's existence: {e}")
            return False

    @staticmethod
    async def verify_installation() -> None:
        # Helper function that verifies playwright & chromium is installed
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                await browser.close()
            print('Playwright and Chromium are successfully installed.')
        except Exception as e:
            print(f'An exception has occurred while attempting to verify installation: {e}')

    @staticmethod
    def chunk_list(items: Collection, chunk_size: int) -> list:
        # Based off of: https://github.com/apache/incubator-sdap-ingester
        return [list(items)[i : i + chunk_size] for i in range(0, len(items), chunk_size)]

    @staticmethod
    async def visit(url: str, proxy: str | None = None) -> tuple[str, str]:
        try:
            timeout = aiohttp.ClientTimeout(total=35)
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/122.0.0.0 Safari/537.36'
            }
            url = f'http://{url}' if not url.startswith('http') else url
            url = url.replace('www.', '')
            sslcontext = ssl.create_default_context(cafile=certifi.where())

            # Create connector based on proxy type
            connector: ProxyConnector | aiohttp.TCPConnector | None = None
            proxy_param = None
            if proxy:
                if proxy.startswith('socks5://'):
                    connector = ProxyConnector.from_url(proxy, ssl=sslcontext)
                else:
                    # HTTP proxy
                    connector = aiohttp.TCPConnector(ssl=sslcontext)
                    proxy_param = proxy
            else:
                connector = aiohttp.TCPConnector(ssl=sslcontext)

            async with aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=connector,
            ) as session:
                async with session.get(url, ssl=False, proxy=proxy_param) as resp:
                    text = await resp.text('UTF-8')
                    return f'http://{url}' if not url.startswith('http') else url, text
        except Exception as e:
            print(f'An exception has occurred while attempting to visit {url} : {e}')
            return '', ''

    async def take_screenshot(self, url: str) -> None:
        url = f'http://{url}' if not url.startswith('http') else url
        url = url.replace('www.', '')
        print(f'Attempting to take a screenshot of: {url}')
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            # New browser context
            context = await browser.new_context()
            page = await context.new_page()
            path = rf'{self.output}{self.slash}{url.replace("http://", "").replace("https://", "")}.png'
            date = str(datetime.now())
            try:
                # Will fail if network idle or load event doesn't fire after
                # 35s which should be handled
                await page.goto(url, timeout=35000)
                await page.screenshot(path=path)
            except Exception as e:
                print(f'An exception has occurred attempting to screenshot: {url} : {e}')
                path = ''
            finally:
                await page.close()
                await context.close()
                await browser.close()
                print(date, url, path)
