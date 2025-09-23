import json as _stdlib_json
from types import ModuleType

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError:
    pass
except Exception:
    pass


class SearchChaos:
    """
    Class uses ProjectDiscovery Chaos subdomain enumeration API
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.proxy = False
        self.hostname = 'https://dns.projectdiscovery.io'
        self.key = self._get_api_key()

    def _get_api_key(self) -> str:
        """Get Chaos API key"""
        try:
            return Core.projectdiscovery_key()
        except Exception:
            raise MissingKey('Chaos (ProjectDiscovery)')

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
            headers = {'User-agent': Core.get_user_agent(), 'Authorization': f'Bearer {self.key}'}

            # Chaos API endpoint for subdomain enumeration
            url = f'{self.hostname}/dns/{self.word}/subdomains'

            response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)

            if not response or not isinstance(response, list) or not response[0]:
                print(f'No response from Chaos API for: {url}')
                return

            try:
                data = self._safe_parse_json(response[0])

                if isinstance(data, dict):
                    # Check for error messages
                    if 'error' in data:
                        error_msg = data.get('message', data.get('error', 'Unknown error'))
                        print(f'Chaos API error: {error_msg}')
                        if 'unauthorized' in error_msg.lower():
                            raise MissingKey('Chaos (ProjectDiscovery)')
                        return

                    # Extract subdomains from response
                    subdomains = data.get('subdomains', [])
                    if not subdomains:
                        subdomains = data.get('data', [])
                    if not subdomains:
                        subdomains = data.get('results', [])

                    if isinstance(subdomains, list):
                        for subdomain in subdomains:
                            if isinstance(subdomain, str):
                                # Chaos returns subdomain names without the root domain
                                # So we need to append the root domain
                                full_domain = f'{subdomain}.{self.word}' if subdomain else self.word
                                self.totalhosts.add(full_domain.lower())
                            elif isinstance(subdomain, dict):
                                # Handle different response formats
                                sub = subdomain.get('subdomain', '') or subdomain.get('name', '')
                                if sub:
                                    full_domain = f'{sub}.{self.word}'
                                    self.totalhosts.add(full_domain.lower())

                elif isinstance(data, list):
                    # Sometimes the response is directly a list
                    for subdomain in data:
                        if isinstance(subdomain, str):
                            full_domain = f'{subdomain}.{self.word}' if subdomain else self.word
                            self.totalhosts.add(full_domain.lower())

            except Exception as e:
                print(f'Failed to parse Chaos response: {e}')

        except MissingKey:
            raise
        except Exception as e:
            print(f'Chaos API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
