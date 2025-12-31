import asyncio

import aiohttp

from theHarvester.lib.core import Core


class SearchThc:
    """Class to search for subdomains using THC (ip.thc.org)."""

    def __init__(self, word: str) -> None:
        self.word = word
        self.results: set = set()
        self.proxy = False
        self.max_retries = 3
        self.base_delay = 2

    async def do_search(self) -> None:
        url = f'https://ip.thc.org/api/v1/subdomains/download?domain={self.word}&limit=10000&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}

        for attempt in range(self.max_retries):
            try:
                timeout = aiohttp.ClientTimeout(total=60)
                async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                    async with session.get(url) as response:
                        if response.status == 429:
                            rate_remaining = response.headers.get('x-ratelimit-remaining', '0')
                            wait_time = self.base_delay * (attempt + 1)
                            print(f'THC rate limit hit (remaining: {rate_remaining}). Waiting {wait_time}s before retry...')
                            await asyncio.sleep(wait_time)
                            continue

                        if response.status != 200:
                            print(f'THC returned status {response.status}')
                            return

                        text = await response.text()
                        if text:
                            for line in text.splitlines():
                                hostname = line.strip().lower()
                                if hostname and self.word.lower() in hostname:
                                    self.results.add(hostname)
                        return

            except Exception as e:
                error_msg = str(e).lower()
                if '429' in error_msg or 'rate' in error_msg:
                    wait_time = self.base_delay * (attempt + 1)
                    print(f'THC rate limit detected. Waiting {wait_time}s before retry...')
                    await asyncio.sleep(wait_time)
                    continue
                print(f'An exception has occurred in THC: {e}')
                return

    async def get_hostnames(self) -> set:
        return self.results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
