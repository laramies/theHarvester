import json as _stdlib_json
from types import ModuleType

from theHarvester.lib.core import AsyncFetcher

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
    print("[*] Using 'ujson' for JSON operations.")
except ImportError as e:
    print(f"'ujson' not available. Falling back to standard 'json' module. Reason: {e}")
except Exception as e:
    print(f"Unexpected error while importing 'ujson'. Falling back to standard 'json'. Reason: {e}")


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

            if not response or not isinstance(response, list) or not response[0]:
                print(f'No response or malformed response from URL: {url}')
                data = {}
            else:
                try:
                    data = self._safe_parse_json(response[0])
                except Exception as e:
                    print(f'Failed to parse JSON from first response: {e}')
                    data = {}

            results = data.get('results', []) if isinstance(data, dict) else []
            if isinstance(results, list):
                self.totalhosts = {host for host in results if isinstance(host, str) and host}
            else:
                print(f"Unexpected data format in 'results' for URL: {url}")

            second_url = f'https://api.threatminer.org/v2/domain.php?q={self.word}&rt=2'
            secondresp = await AsyncFetcher.fetch_all([second_url], json=False, proxy=self.proxy)

            if not secondresp or not isinstance(secondresp, list) or not secondresp[0]:
                print(f'No response or malformed response from URL: {second_url}')
                second = {}
            else:
                try:
                    second = self._safe_parse_json(secondresp[0])
                except Exception as e:
                    print(f'Failed to parse JSON from second response: {e}')
                    second = {}

            second_results = second.get('results', []) if isinstance(second, dict) else []
            if isinstance(second_results, list):
                self.totalips = {item.get('ip') for item in second_results if isinstance(item, dict) and item.get('ip')}
            else:
                print(f"Unexpected data format in second 'results' from URL: {second_url}")

        except Exception as e:
            print(f'ThreatMiner API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
