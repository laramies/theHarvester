from theHarvester.lib.core import AsyncFetcher
try:
    import ujson as json
except ImportError:
    import json


class SearchThreatminer:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False

    @staticmethod
    def _safe_parse_json(payload: object) -> dict:
        # If already a dict, return it; if string, try parse; else return {}
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, str):
            try:
                return json.loads(payload)
            except Exception:
                return {}
        return {}

    async def do_search(self) -> None:
        try:
            url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=5'
            response = await AsyncFetcher.fetch_all([url], json=False, proxy=self.proxy)
            data = self._safe_parse_json(response[0]) if response else {}
            results = data.get('results', []) if isinstance(data, dict) else []
            if isinstance(results, list):
                self.totalhosts = {host for host in results if isinstance(host, str) and host}

            second_url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=2'
            secondresp = await AsyncFetcher.fetch_all([second_url], json=False, proxy=self.proxy)
            second = self._safe_parse_json(secondresp[0]) if secondresp else {}
            second_results = second.get('results', []) if isinstance(second, dict) else []
            if isinstance(second_results, list):
                try:
                    self.totalips = {
                        item.get('ip')
                        for item in second_results
                        if isinstance(item, dict) and item.get('ip')
                    }
                except Exception:
                    pass
        except Exception as e:
            print(f'ThreatMiner API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
