from theHarvester.lib.core import AsyncFetcher, Core


class SearchThc:
    """Class to search for subdomains using THC (ip.thc.org)."""

    def __init__(self, word: str) -> None:
        self.word = word
        self.results: set = set()
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://ip.thc.org/api/v1/subdomains/download?domain={self.word}&limit=10000&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            responses = await AsyncFetcher.fetch_all(
                [url],
                headers=headers,
                proxy=self.proxy,
            )
            if responses and responses[0]:
                for line in responses[0].splitlines():
                    hostname = line.strip().lower()
                    if hostname and self.word.lower() in hostname:
                        self.results.add(hostname)
        except Exception as e:
            print(f'An exception has occurred in THC: {e}')

    async def get_hostnames(self) -> set:
        return self.results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
