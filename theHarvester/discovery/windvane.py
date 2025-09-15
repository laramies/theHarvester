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


class SearchWindvane:
    """
    Class uses the Windvane API to gather subdomains and domain intelligence
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.totalemails: set = set()
        self.proxy = False
        self.hostname = 'https://windvane.lichoin.com'

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
            headers = {
                'User-agent': Core.get_user_agent(),
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Based on the API documentation, this appears to be the general endpoint structure
            # Note: This is a basic implementation as the actual API might require authentication
            
            # Try subdomain enumeration endpoint
            subdomain_url = f'{self.hostname}/api/subdomain'
            subdomain_data = {
                'domain': self.word,
                'type': 'subdomain'
            }
            
            try:
                # POST request for subdomain search
                response = await AsyncFetcher.fetch_all([subdomain_url], 
                                                      headers=headers, 
                                                      proxy=self.proxy,
                                                      json=False)

                if response and isinstance(response, list) and response[0]:
                    try:
                        data = self._safe_parse_json(response[0])
                        
                        # Extract subdomains from response
                        if isinstance(data, dict):
                            # Try different possible response structures
                            subdomains = data.get('subdomains', [])
                            if not subdomains:
                                subdomains = data.get('data', [])
                            if not subdomains:
                                subdomains = data.get('results', [])
                                
                            if isinstance(subdomains, list):
                                for subdomain in subdomains:
                                    if isinstance(subdomain, str):
                                        if subdomain.endswith(self.word):
                                            self.totalhosts.add(subdomain.lower())
                                    elif isinstance(subdomain, dict):
                                        # Handle dict format with subdomain field
                                        sd_name = subdomain.get('subdomain', '') or subdomain.get('domain', '') or subdomain.get('name', '')
                                        if sd_name and sd_name.endswith(self.word):
                                            self.totalhosts.add(sd_name.lower())
                                        
                                        # Extract IPs if available
                                        ip = subdomain.get('ip', '') or subdomain.get('address', '')
                                        if ip and self._is_valid_ip(ip):
                                            self.totalips.add(ip)
                                            
                    except Exception as e:
                        print(f'Failed to parse Windvane subdomain response: {e}')
            except Exception as e:
                print(f'Windvane subdomain API request failed: {e}')

            # Try domain intelligence endpoint
            intel_url = f'{self.hostname}/api/domain'
            intel_data = {
                'domain': self.word,
                'type': 'intelligence'
            }
            
            try:
                intel_response = await AsyncFetcher.fetch_all([intel_url], 
                                                            headers=headers, 
                                                            proxy=self.proxy,
                                                            json=False)

                if intel_response and isinstance(intel_response, list) and intel_response[0]:
                    try:
                        intel_data = self._safe_parse_json(intel_response[0])
                        
                        if isinstance(intel_data, dict):
                            # Extract additional hosts
                            hosts = intel_data.get('hosts', []) or intel_data.get('domains', [])
                            if isinstance(hosts, list):
                                for host in hosts:
                                    if isinstance(host, str) and host.endswith(self.word):
                                        self.totalhosts.add(host.lower())
                                        
                            # Extract emails
                            emails = intel_data.get('emails', [])
                            if isinstance(emails, list):
                                for email in emails:
                                    if isinstance(email, str) and self.word in email:
                                        self.totalemails.add(email.lower())
                                        
                    except Exception as e:
                        print(f'Failed to parse Windvane intelligence response: {e}')
            except Exception as e:
                print(f'Windvane intelligence API request failed: {e}')

        except Exception as e:
            print(f'Windvane API error: {e}')

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate if string is a valid IP address"""
        try:
            parts = ip.split('.')
            return (len(parts) == 4 and 
                   all(0 <= int(part) <= 255 for part in parts))
        except (ValueError, TypeError):
            return False

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips
        
    async def get_emails(self) -> set:
        return self.totalemails

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
