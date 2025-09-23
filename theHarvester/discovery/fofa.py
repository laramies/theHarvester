import base64
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


class SearchFofa:
    """
    Class uses Fofa API to search for domain and host intelligence
    Fofa is a Chinese search engine for network-connected devices
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False
        self.hostname = 'https://fofa.info'
        self.api_key, self.email = self._get_api_credentials()

    def _get_api_credentials(self) -> tuple[str, str]:
        """Get Fofa API credentials"""
        try:
            return Core.fofa_key()
        except Exception:
            raise MissingKey('Fofa API (key and email required)')

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

            # Fofa search query - encode in base64
            query = f'domain="{self.word}"'
            query_encoded = base64.b64encode(query.encode()).decode()

            # Fofa API endpoint
            url = f'{self.hostname}/api/v1/search/all'
            params = {
                'email': self.email,
                'key': self.api_key,
                'qbase64': query_encoded,
                'fields': 'host,ip,port,protocol,title',
                'size': 100,  # Limit results
            }

            # Build URL with parameters
            param_string = '&'.join([f'{k}={v}' for k, v in params.items()])
            full_url = f'{url}?{param_string}'

            response = await AsyncFetcher.fetch_all([full_url], headers=headers, proxy=self.proxy)

            if not response or not isinstance(response, list) or not response[0]:
                print(f'No response from Fofa API for: {self.word}')
                return

            try:
                data = self._safe_parse_json(response[0])

                if isinstance(data, dict):
                    # Check for errors
                    if data.get('error', False):
                        error_msg = data.get('errmsg', 'Unknown error')
                        print(f'Fofa API error: {error_msg}')
                        if '账号无效' in error_msg or 'invalid' in error_msg.lower():
                            raise MissingKey('Fofa API (Invalid credentials)')
                        return

                    # Extract results
                    results = data.get('results', [])
                    if isinstance(results, list):
                        for result in results:
                            if isinstance(result, list) and len(result) >= 2:
                                host = result[0]  # host field
                                ip = result[1]  # ip field

                                # Add host if it's related to our domain
                                if isinstance(host, str) and self.word in host:
                                    # Extract clean hostname
                                    clean_host = host.replace('http://', '').replace('https://', '').split(':')[0]
                                    if clean_host.endswith(f'.{self.word}') or clean_host == self.word:
                                        self.totalhosts.add(clean_host.lower())

                                # Add IP
                                if isinstance(ip, str) and ip:
                                    self.totalips.add(ip)

            except Exception as e:
                print(f'Failed to parse Fofa response: {e}')

        except MissingKey:
            raise
        except Exception as e:
            print(f'Fofa API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
