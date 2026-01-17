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


class SearchLeakix:
    """
    Class uses LeakIX API to search for domain leaks and subdomains
    Note: LeakIX requires API key for most endpoints
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalemails: set = set()
        self.proxy = False
        self.hostname = 'https://leakix.net'

    @staticmethod
    def _safe_parse_json(payload: object) -> list:
        # If already a list, return it; if string, try parse; else return []
        if isinstance(payload, list):
            return payload
        if isinstance(payload, str):
            try:
                result = json.loads(payload)
                return result if isinstance(result, list) else [result] if isinstance(result, dict) else []
            except Exception:
                return []
        return []

    async def do_search(self) -> None:
        try:
            headers = {
                'User-agent': Core.get_user_agent(),
                'accept': 'application/json',
            }

            # Add API key if available
            api_key = Core.leakix_key()
            if api_key:
                headers['api-key'] = api_key

            search_queries = [
                f'{self.hostname}/api/subdomains/{self.word}',
                f'{self.hostname}/host/{self.word}',
            ]

            for query_url in search_queries:
                try:
                    response = await AsyncFetcher.fetch_all([query_url], headers=headers, proxy=self.proxy)

                    if not response or not isinstance(response, list) or not response[0]:
                        continue

                    # Check if the response is an error message
                    if isinstance(response[0], str) and (
                        'Incorrect API Key' in response[0]
                        or 'unauthorized' in response[0].lower()
                        or 'error' in response[0].lower()
                    ):
                        print(f'LeakIX API requires authentication: {response[0][:100]}')
                        continue

                    try:
                        data = self._safe_parse_json(response[0])

                        for item in data:
                            if isinstance(item, dict):
                                # Extract hostnames from different fields
                                hostname = item.get('hostname', '') or item.get('host', '') or item.get('domain', '')
                                if hostname and (hostname.endswith(f'.{self.word}') or hostname == self.word):
                                    self.totalhosts.add(hostname.lower())

                                # Extract emails if available
                                email = item.get('email', '') or item.get('username', '')
                                if email and '@' in email and self.word in email:
                                    self.totalemails.add(email.lower())

                                # Check for subdomains in other fields
                                for field in ['subdomain', 'target', 'service_name']:
                                    value = item.get(field, '')
                                    if value and isinstance(value, str):
                                        if value.endswith(f'.{self.word}') or value == self.word:
                                            self.totalhosts.add(value.lower())

                    except Exception as e:
                        print(f'Failed to parse LeakIX response: {e}')

                except Exception as e:
                    print(f'LeakIX API error for {query_url}: {e}')
                    continue

        except Exception as e:
            print(f'LeakIX API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_emails(self) -> set:
        return self.totalemails

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
