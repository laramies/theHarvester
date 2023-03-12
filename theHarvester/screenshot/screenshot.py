"""
Screenshot module that utilizes pyppeteer to asynchronously
take screenshots
"""

from pyppeteer import launch
import aiohttp
import asyncio
import certifi
from datetime import datetime
import os
import ssl
import sys
from typing import Sized, Tuple


class ScreenShotter:

    def __init__(self, output) -> None:
        self.output = output
        self.slash = "\\" if 'win' in sys.platform else '/'
        self.slash = "" if (self.output[-1] == "\\" or self.output[-1] == "/") else self.slash

    def verify_path(self) -> bool:
        try:
            if not os.path.isdir(self.output):
                answer = input(
                    '[+] The output path you have entered does not exist would you like to create it (y/n): ')
                if answer.lower() == 'yes' or answer.lower() == 'y':
                    os.mkdir(self.output)
                    return True
                else:
                    return False
            return True
        except Exception as e:
            print(f"An exception has occurred while attempting to verify output path's existence: {e}")
            return False

    @staticmethod
    async def verify_installation() -> None:
        # Helper function that verifies pyppeteer & chromium are installed
        # If chromium is not installed pyppeteer will prompt user to install it
        browser = await launch(headless=True, ignoreHTTPSErrors=True, args=["--no-sandbox"])
        await browser.close()

    @staticmethod
    def chunk_list(items: Sized, chunk_size):
        # Based off of: https://github.com/apache/incubator-sdap-ingester
        return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]

    @staticmethod
    async def visit(url: str) -> Tuple[str, str]:
        try:
            # print(f'attempting to visit: {url}')
            timeout = aiohttp.ClientTimeout(total=35)
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                     'Chrome/83.0.4103.106 Safari/537.36'}
            url = f'http://{url}' if not url.startswith('http') else url
            url = url.replace('www.', '')
            sslcontext = ssl.create_default_context(cafile=certifi.where())
            async with aiohttp.ClientSession(timeout=timeout, headers=headers,
                                             connector=aiohttp.TCPConnector(ssl=sslcontext)) as session:
                async with session.get(url, verify_ssl=False) as resp:
                    # TODO fix with origin url, should be there somewhere
                    text = await resp.text("UTF-8")
                    return f'http://{url}' if not url.startswith('http') else url, text
        except Exception as e:
            print(f'An exception has occurred while attempting to visit {url} : {e}')
            return "", ""

    async def take_screenshot(self, url: str) -> Tuple[str, ...]:
        url = f'http://{url}' if not url.startswith('http') else url
        url = url.replace('www.', '')
        print(f'Attempting to take a screenshot of: {url}')
        browser = await launch(headless=True, ignoreHTTPSErrors=True, args=["--no-sandbox"])
        context = await browser.createIncognitoBrowserContext()
        # Create a new page in a pristine context.
        page = await context.newPage()
        path = fr'{self.output}{self.slash}{url.replace("http://", "").replace("https://", "")}.png'
        date = str(datetime.utcnow())
        try:
            # change default timeout from 30 to 35 seconds
            page.setDefaultNavigationTimeout(35000)
            await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                    'Chrome/83.0.4103.106 Safari/537.36')
            await page.goto(url)
            await page.screenshot({'path': path})
        except Exception as e:
            print(f'An exception has occurred attempting to screenshot: {url} : {e}')
            path = ""
        finally:
            # Clean up everything whether screenshot is taken or not
            await asyncio.sleep(2)
            await page.close()
            await context.close()
            await browser.close()
            return date, url, path
