import asyncio
from urllib.parse import quote

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser


class SearchBrave:
    def __init__(self, word, limit):
        self.word = word
        self.results = []
        self.totalresults = ''
        self.api_key = Core.brave_key()
        if self.api_key is None or self.api_key == '':
            raise MissingKey('Brave Search')
        self.server = 'https://api.search.brave.com/res/v1/web/search'
        self.limit = limit
        self.proxy = False
        self.rate_limit_delay = 1  # Initial delay for rate limiting

    async def do_search(self):
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'gzip', 'X-Subscription-Token': self.api_key}

        # Search queries: exact match and site-specific
        queries = [f'"{self.word}"', f'site:{self.word}']

        for query in queries:
            try:
                # Calculate number of pages based on limit (20 results per page)
                pages = min((self.limit // 20) + 1, 5)  # Maximum 5 pages

                for offset in range(0, pages * 20, 20):
                    params = {
                        'q': query,
                        'count': min(20, self.limit - len(self.results)),
                        'offset': offset,
                        'safesearch': 'off',
                        'freshness': 'all',
                        'extra_snippets': 'true',  # Enable extra snippets for richer content
                        'text_decorations': 'true',  # Enable highlighting
                        'spellcheck': 'true',  # Enable spellcheck
                    }

                    # Build URL with parameters
                    param_string = '&'.join([f'{k}={quote(str(v))}' for k, v in params.items()])
                    url = f'{self.server}?{param_string}'

                    resp = await AsyncFetcher.fetch(url=url, headers=headers, proxy=self.proxy, json=True)

                    # Handle API response
                    if resp is None:
                        print('No response received from Brave Search API')
                        break

                    # Check for API errors (rate limit, quota exceeded, etc.)
                    if 'error' in resp:
                        error_msg = resp.get('error', {}).get('message', 'Unknown API error')
                        error_code = resp.get('error', {}).get('code', 'unknown')

                        if 'rate limit' in error_msg.lower() or error_code == 'rate_limit_exceeded':
                            print(f'Rate limit exceeded. Increasing delay to {self.rate_limit_delay * 2} seconds')
                            self.rate_limit_delay *= 2
                            await asyncio.sleep(self.rate_limit_delay)
                            continue
                        elif 'quota' in error_msg.lower() or error_code == 'quota_exceeded':
                            print(f'API quota exceeded: {error_msg}')
                            break
                        else:
                            # print(f'API error ({error_code}): {error_msg}')
                            break

                    if 'web' in resp and 'results' in resp['web']:
                        results = resp['web']['results']
                        if not results:
                            break

                        # Extract text content from results for parsing (including extra snippets)
                        for result in results:
                            result_text = f'{result.get("title", "")} {result.get("description", "")}'

                            # Add extra snippets if available
                            if 'extra_snippets' in result:
                                for snippet in result['extra_snippets']:
                                    result_text += f' {snippet}'

                            result_text += f' {result.get("url", "")}'
                            self.totalresults += result_text + '\n'

                        self.results.extend(results)

                        # Stop if we've reached our limit
                        if len(self.results) >= self.limit:
                            break
                    else:
                        print('Unexpected response format from Brave Search API')
                        break

                    await asyncio.sleep(get_delay())

            except Exception as e:
                error_msg = str(e).lower()

                # Handle specific API-related exceptions
                if 'rate limit' in error_msg or '429' in error_msg:
                    print(f'Rate limit detected in exception. Increasing delay to {self.rate_limit_delay * 2} seconds')
                    self.rate_limit_delay *= 2
                    await asyncio.sleep(self.rate_limit_delay)
                elif 'quota' in error_msg or '403' in error_msg:
                    print(f'Quota exceeded or access denied: {e}')
                    break
                elif 'timeout' in error_msg:
                    print(f'Request timeout occurred: {e}')
                    await asyncio.sleep(get_delay() + 2)
                else:
                    print(f'An exception has occurred in bravesearch: {e}')
                    await asyncio.sleep(get_delay() + 5)
                continue

    async def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
