from theHarvester.lib.core import AsyncFetcher


class SearchThreatminer:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False

    async def do_search(self) -> None:
        try:
            url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=5'
            response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
            if response and isinstance(response[0], dict) and 'results' in response[0]:
                self.totalhosts = {host for host in response[0]['results'] if host}
            
            second_url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=2'
            secondresp = await AsyncFetcher.fetch_all([second_url], json=True, proxy=self.proxy)
            if secondresp and isinstance(secondresp[0], dict) and 'results' in secondresp[0]:
                try:
                    self.totalips = {resp['ip'] for resp in secondresp[0]['results'] if 'ip' in resp and resp['ip']}
                except (TypeError, KeyError):
                    pass
        except Exception as e:
            print(f'ThreatMiner API error: {e}')
            # Continue with empty results rather than failing completely

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
