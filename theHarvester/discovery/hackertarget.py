# theHarvester/discovery/hackertarget.py
from theHarvester.lib.core import AsyncFetcher, Core


class SearchHackerTarget:
    """
    Class uses the HackerTarget API to gather subdomains and IPs.

    This version supports reading a Hackertarget API key (if present) and
    appending it to the hackertarget request URLs as `apikey=<key>`.
    """

    def __init__(self, word) -> None:
        self.word = word
        self.total_results = ''
        self.hostname = 'https://api.hackertarget.com'
        self.proxy = False
        self.results = None
        self.key = Core.hackertarget_key()

    async def do_search(self) -> None:
        headers = {'User-agent': Core.get_user_agent()}

        # base URLs used by the original implementation
        base_urls = [
            f'{self.hostname}/hostsearch/?q={self.word}',
            f'{self.hostname}/reversedns/?q={self.word}',
        ]

        # if user supplied an API key in api-keys.yml (or repo loader), append it
        if self.key:
            request_urls = [f'{u}&apikey={self.key}' for u in base_urls]
        else:
            request_urls = base_urls

        # fetch all using existing AsyncFetcher helper
        responses = await AsyncFetcher.fetch_all(request_urls, headers=headers, proxy=self.proxy)

        # the original code concatenated responses and replaced commas with colons
        for response in responses:
            # response is expected to be a string; keep the original behavior
            self.total_results += response.replace(',', ':')

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_hostnames(self) -> list:
        return [result for result in self.total_results.splitlines() if 'No PTR records found' not in result]
