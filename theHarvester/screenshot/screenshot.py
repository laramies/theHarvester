"""
Screenshot module that utilizes pyppeteer in async fashion
to break urls into list and assign them to workers in a queue
"""

from pyppeteer import launch
import aiohttp
import sys

class ScreenShotter():

    def __init__(self, output):
        self.output = output
        self.slash = "\\" if 'win' in sys.platform else '/'
        self.slash = "" if (self.output[-1] == "\\" or self.output[-1] == "/") else self.slash

    @staticmethod
    def _chunk_list(items, chunk_size):
        return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]

    @staticmethod
    async def visit(url):
        try:
            print(f'attempting to visit: {url}')
            timeout = aiohttp.ClientTimeout(total=45)
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                     'Chrome/83.0.4103.106 Safari/537.36'}
            url = f'http://{url}' if ('http' not in url and 'https' not in url) else url
            url = url.replace('www.', '')
            async with aiohttp.ClientSession(timeout=timeout, headers=headers,
                                             connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
                async with session.get(url) as resp:
                    # TODO fix with origin url I think it's there somewhere
                    #return str(resp.url.origin()), await resp.text()
                    text = await resp.text("UTF-8")
                    print(text)
                    print('\n\n\n\n')
                    return f'http://{url}' if ('http' not in url and 'https' not in url) else url, text
        except Exception as e:
            print(f'An exception has occurred while attempting to visit: {e}')
            return "", ""

    async def take_screenshot(self, url):
        url = f'http://{url}' if ('http' not in url and 'https' not in url) else url
        # url = f'https://{url}' if ('http' not in url and 'https' not in url) else url
        url = url.replace('www.', '')
        print(f'Taking a screenshot of: {url}')
        browser = await launch(headless=True, ignoreHTTPSErrors=True, args=["--no-sandbox"])
        context = await browser.createIncognitoBrowserContext()
        page = await browser.newPage()
        try:

            # change default timeout from 30 to 35 seconds
            page.setDefaultNavigationTimeout(35000)
            await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                    'Chrome/83.0.4103.106 Safari/537.36')
            #await page.goto(url, waitUntil='networkidle0')
            await page.goto(url)
            await page.screenshot({'path': f'{self.output}{self.slash}{url.replace("http://", "").replace("https://", "")}.png'})
            #print('inside try and page has been closed')
            #await page.close()
            # await browser.close()
            # return True
        except Exception as e:
            print(f'Exception occurred: {e} for: {url} ')
        finally:
            await page.close()
            #await page.close()
            #print('page is closed')
            await context.close()
            #print('context is closed')
            await browser.close()
            print('everything is closed!')
