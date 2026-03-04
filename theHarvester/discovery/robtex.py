import json as _stdlib_json
from types import ModuleType

import aiohttp

from theHarvester.lib.core import AsyncFetcher, Core

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError as e:
    print(f"'ujson' not available. Falling back to standard 'json' module. Reason: {e}")
except (AttributeError, OSError, RuntimeError, SystemError, ValueError) as e:
    print(f"Unexpected error while importing 'ujson'. Falling back to standard 'json'. Reason: {e}")


class SearchRobtex:
    """
    Class uses the Robtex passive DNS API to gather subdomains
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False
        self.hostname = 'https://freeapi.robtex.com'

    @staticmethod
    def _safe_parse_json_lines(payload: str) -> list:
        """Parse JSONL (JSON Lines) format"""
        results: list = []
        if not payload:
            return results

        for line in payload.strip().split('\n'):
            if line.strip():
                try:
                    results.append(json.loads(line))
                except (TypeError, ValueError):
                    continue
        return results

    async def do_search(self) -> None:
        try:
            headers = {'User-agent': Core.get_user_agent()}

            # Use passive DNS forward lookup to get subdomains
            url = f'{self.hostname}/pdns/forward/{self.word}'
            response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)

            if not response or not isinstance(response, list) or not response[0]:
                print(f'No response from Robtex API for: {url}')
                return

            try:
                data = self._safe_parse_json_lines(response[0])
            except (TypeError, ValueError) as e:
                print(f'Failed to parse JSON lines from Robtex response: {e}')
                return

            # Extract subdomains from DNS records
            for record in data:
                if isinstance(record, dict):
                    # Get the hostname from rrdata field for different record types
                    rrdata = record.get('rrdata', '')
                    rrtype = record.get('rrtype', '')
                    rrname = record.get('rrname', '')

                    # Add the original domain name
                    if rrname and rrname.endswith(self.word):
                        self.totalhosts.add(rrname)

                    # For CNAME records, the rrdata contains hostnames
                    if rrtype == 'CNAME' and rrdata:
                        if rrdata.endswith(self.word) or f'.{self.word}' in rrdata:
                            self.totalhosts.add(rrdata.rstrip('.'))

                    # For A records, we can get IPs
                    if rrtype == 'A' and rrdata:
                        try:
                            # Validate it's an IP
                            parts = rrdata.split('.')
                            if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                                self.totalips.add(rrdata)
                        except (ValueError, TypeError):
                            pass

            # Also try reverse DNS lookup for additional data
            reverse_url = f'{self.hostname}/pdns/reverse/{self.word}'
            reverse_response = await AsyncFetcher.fetch_all([reverse_url], headers=headers, proxy=self.proxy)

            if reverse_response and isinstance(reverse_response, list) and reverse_response[0]:
                try:
                    reverse_data = self._safe_parse_json_lines(reverse_response[0])
                    for record in reverse_data:
                        if isinstance(record, dict):
                            rrdata = record.get('rrdata', '')
                            if rrdata and (rrdata.endswith(self.word) or f'.{self.word}' in rrdata):
                                self.totalhosts.add(rrdata.rstrip('.'))
                except (TypeError, ValueError) as e:
                    print(f'Failed to parse reverse DNS data from Robtex: {e}')

        except (aiohttp.ClientError, TimeoutError, OSError, TypeError, ValueError) as e:
            print(f'Robtex API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
