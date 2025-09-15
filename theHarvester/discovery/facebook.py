import json as _stdlib_json
from types import ModuleType
import re

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


class SearchFacebook:
    """
    Class uses Facebook Certificate Transparency API to find certificates and subdomains
    Note: Facebook CT API is scheduled for deprecation by end of 2025
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.proxy = False
        self.hostname = 'https://graph.facebook.com'
        self.app_id, self.app_secret = self._get_api_credentials()

    def _get_api_credentials(self) -> tuple[str, str]:
        """Get Facebook API credentials"""
        try:
            # Note: Facebook API requires app_id and app_secret or access_token
            # Since theHarvester doesn't have specific Facebook keys in core.py,
            # we'll use a generic approach
            api_keys = Core.api_keys()
            if 'facebook' in api_keys:
                return api_keys['facebook'].get('app_id', ''), api_keys['facebook'].get('app_secret', '')
            else:
                raise MissingKey('Facebook CT API (app_id and app_secret required)')
        except Exception:
            raise MissingKey('Facebook CT API (app_id and app_secret required)')

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

    def _extract_domain_from_cert(self, cert_data: dict) -> set:
        """Extract domains from certificate data"""
        domains = set()
        
        # Check common certificate fields
        for field in ['domains', 'certificate_domains', 'subject_name', 'issuer_name']:
            if field in cert_data:
                value = cert_data[field]
                if isinstance(value, list):
                    for domain in value:
                        if isinstance(domain, str) and (domain.endswith(f'.{self.word}') or domain == self.word):
                            domains.add(domain.lower())
                elif isinstance(value, str):
                    if value.endswith(f'.{self.word}') or value == self.word:
                        domains.add(value.lower())
        
        # Check subject alternative names
        san = cert_data.get('subject_alternative_names', [])
        if isinstance(san, list):
            for name in san:
                if isinstance(name, str):
                    # Remove wildcards and clean up
                    clean_name = name.replace('*.', '').replace('*', '')
                    if clean_name.endswith(f'.{self.word}') or clean_name == self.word:
                        domains.add(clean_name.lower())
                    # Also add the original wildcard domain if it's meaningful
                    if name.startswith('*.') and name[2:].endswith(f'.{self.word}'):
                        domains.add(name[2:].lower())
        
        return domains

    async def do_search(self) -> None:
        try:
            # Generate access token using app credentials
            access_token = f"{self.app_id}|{self.app_secret}"
            
            headers = {
                'User-agent': Core.get_user_agent(),
            }
            
            # Facebook Certificate Transparency API endpoint
            # Note: This API is being deprecated by end of 2025
            params = {
                'access_token': access_token,
                'query': self.word,
                'fields': 'domains,certificate_domains,subject_name,issuer_name,subject_alternative_names'
            }
            
            # Construct URL with parameters
            param_string = '&'.join([f"{k}={v}" for k, v in params.items()])
            url = f'{self.hostname}/certificates?{param_string}'
            
            response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)

            if not response or not isinstance(response, list) or not response[0]:
                print(f'No response from Facebook CT API for: {self.word}')
                return

            try:
                data = self._safe_parse_json(response[0])
                
                if isinstance(data, dict):
                    # Check for API errors
                    if 'error' in data:
                        error_info = data['error']
                        error_msg = error_info.get('message', 'Unknown error')
                        error_code = error_info.get('code', 0)
                        
                        print(f'Facebook CT API error: {error_msg} (Code: {error_code})')
                        
                        if error_code == 200:  # Invalid app ID
                            raise MissingKey('Facebook CT API (Invalid app_id or app_secret)')
                        return
                    
                    # Extract certificate data
                    cert_data = data.get('data', [])
                    if isinstance(cert_data, list):
                        for certificate in cert_data:
                            if isinstance(certificate, dict):
                                domains = self._extract_domain_from_cert(certificate)
                                self.totalhosts.update(domains)
                    
                    # Handle pagination if present
                    paging = data.get('paging', {})
                    if 'next' in paging:
                        # For simplicity, we'll limit to first page
                        # Could implement pagination here if needed
                        pass

            except Exception as e:
                print(f'Failed to parse Facebook CT response: {e}')

        except MissingKey:
            raise
        except Exception as e:
            print(f'Facebook CT API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
