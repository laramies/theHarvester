import asyncio

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import securitytrailsparser


class SearchSecuritytrail:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.security_trails_key()
        if self.key is None:
            raise MissingKey('Securitytrail')
        self.results = ''
        self.totalresults = ''
        self.api = 'https://api.securitytrails.com/v1/'
        self.info: tuple[set, set] = (set(), set())
        self.proxy = False
        # Hold structured responses for robust parsing
        self.domain_data: dict = {}
        self.subdomains_data: dict = {}

    async def authenticate(self) -> None:
        # Method to authenticate API key before sending requests.
        headers = {'APIKEY': self.key}
        url = f'{self.api}ping'
        auth_responses = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
        auth_responses = auth_responses[0]
        if 'False' in auth_responses or 'Invalid authentication' in auth_responses:
            print('\tKey could not be authenticated exiting program.')
        await asyncio.sleep(5)

    async def do_search(self) -> None:
        try:
            # https://api.securitytrails.com/v1/domain/domain.com
            domain_url = f'{self.api}domain/{self.word}'
            headers = {'APIKEY': self.key, 'Accept': 'application/json'}
            # Request JSON payloads for robust parsing
            domain_response = await AsyncFetcher.fetch_all([domain_url], headers=headers, json=True, proxy=self.proxy)
            await asyncio.sleep(5)  # 2+ seconds is required due to rate limit.

            if domain_response and isinstance(domain_response[0], dict | list):
                self.domain_data = domain_response[0] if isinstance(domain_response[0], dict) else {}
            else:
                print('SecurityTrails: No JSON response received for domain query')
                # keep legacy string totalresults for any downstream reliance
                if domain_response and domain_response[0]:
                    self.results = str(domain_response[0])
                    self.totalresults += self.results
                return

            # Get subdomains now.
            subdomains_url = f'{domain_url}/subdomains'
            subdomain_response = await AsyncFetcher.fetch_all([subdomains_url], headers=headers, json=True, proxy=self.proxy)
            await asyncio.sleep(5)

            if subdomain_response and isinstance(subdomain_response[0], dict | list):
                self.subdomains_data = subdomain_response[0] if isinstance(subdomain_response[0], dict) else {}
            else:
                print('SecurityTrails: No JSON response received for subdomain query')
                if subdomain_response and subdomain_response[0]:
                    self.results = str(subdomain_response[0])
                    self.totalresults += self.results
        except Exception as e:
            print(f'SecurityTrails API error: {e}')
            return

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.authenticate()
        await self.do_search()
        # Prefer structured JSON if available; fallback to legacy text
        combined_payload = None
        if isinstance(self.domain_data, dict) or isinstance(self.subdomains_data, dict):
            combined_payload = {
                'domain': self.domain_data if isinstance(self.domain_data, dict) else {},
                'subdomains': self.subdomains_data if isinstance(self.subdomains_data, dict) else {},
            }
        parser_input = (
            combined_payload
            if combined_payload and (combined_payload['domain'] or combined_payload['subdomains'])
            else self.totalresults
        )
        parser = securitytrailsparser.Parser(word=self.word, text=parser_input)
        self.info = await parser.parse_text()
        # Create parser and set self.info to tuple returned from parsing text.

    async def get_ips(self) -> set:
        return self.info[0]

    async def get_hostnames(self) -> set:
        return self.info[1]
