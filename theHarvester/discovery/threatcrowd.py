import json as _stdlib_json
from types import ModuleType

from theHarvester.lib.core import AsyncFetcher, Core

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError:
    pass
except Exception:
    pass


class SearchThreatcrowd:
    """
    Class uses ThreatCrowd API to gather domain intelligence and subdomains

    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False
        self.hostname = 'http://ci-www.threatcrowd.org'

    @staticmethod
    def _safe_parse_json(payload: object) -> dict:
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
            headers = {'User-agent': Core.get_user_agent()}

            # ThreatCrowd domain report API
            url = f'{self.hostname}/searchApi/v2/domain/report/?domain={self.word}'

            response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)

            if not response or not isinstance(response, list) or not response[0]:
                print(f'No response from ThreatCrowd API for: {self.word}')
                return

            try:
                data = self._safe_parse_json(response[0])

                if isinstance(data, dict):
                    # Check response code - '1' means success in ThreatCrowd API
                    response_code = data.get('response_code', '')
                    if response_code and response_code != '1':
                        print(f'ThreatCrowd API returned error code: {response_code}')
                        return

                    # Extract subdomains - direct list in response
                    subdomains = data.get('subdomains', [])
                    if isinstance(subdomains, list):
                        for subdomain in subdomains:
                            if isinstance(subdomain, str) and subdomain.strip():
                                # ThreatCrowd returns full subdomains, not relative ones
                                clean_subdomain = subdomain.strip().lower()
                                if clean_subdomain.endswith(f'.{self.word}') or clean_subdomain == self.word:
                                    self.totalhosts.add(clean_subdomain)

                    # Extract IPs if available (from resolutions)
                    resolutions = data.get('resolutions', [])
                    if isinstance(resolutions, list):
                        for resolution in resolutions:
                            if isinstance(resolution, dict):
                                ip = resolution.get('ip_address', '')
                                if ip and ip.strip():
                                    self.totalips.add(ip.strip())
                            elif isinstance(resolution, str):
                                # Sometimes IPs are directly in the list
                                if resolution.strip():
                                    self.totalips.add(resolution.strip())

            except Exception as e:
                print(f'Failed to parse ThreatCrowd response: {e}')

        except Exception as e:
            print(f'ThreatCrowd API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
