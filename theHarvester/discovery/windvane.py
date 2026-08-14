import json as _stdlib_json
import logging
from types import ModuleType

from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.lib.hostnames import normalize_scoped_hostname

logger = logging.getLogger(__name__)

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError:
    pass
except Exception:
    pass


class SearchWindvane:
    """Class uses the Windvane API to gather subdomains and domain intelligence
    API Documentation: https://windvane.lichoin.com

    The API provides several endpoints:
    - /ListSubDomain - Subdomain enumeration
    - /ListDNS - DNS history analysis
    - /ListDomainWhois - Historical whois lookup
    - /ListEmail - Domain name email query

    Note: This API requires authentication for full access.
    - With API key: Full access to all endpoints with pagination
    - Without API key: Limited unauthenticated API access

    Set API key via:
    - Environment variable: export WINDVANE_API_KEY="your-key"
    - Or call search.set_api_key("your-key")
    """

    def __init__(self, word) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.totalemails: set = set()
        self.proxy = False
        self.hostname = 'https://windvane.lichoin.com/trpc.backendhub.public.WindvaneService'
        self.api_key = self._get_api_key()

    def _add_host(self, value: object) -> bool:
        if (hostname := normalize_scoped_hostname(value, self.word)) and hostname != self.word:
            self.totalhosts.add(hostname)
            return True
        return False

    def _add_email(self, value: object) -> None:
        if not isinstance(value, str) or '@' not in value:
            return
        local_part, domain = value.rsplit('@', 1)
        if local_part and (normalized_domain := normalize_scoped_hostname(domain, self.word)):
            self.totalemails.add(f'{local_part.lower()}@{normalized_domain}')

    def _get_api_key(self) -> str | None:
        try:
            return Core.windvane_key()
        except Exception:
            # API key is optional for windvane - returns None for limited access
            return None

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
        """Main search function that queries multiple Windvane API endpoints"""
        try:
            headers = {'User-agent': Core.get_user_agent(), 'Content-Type': 'application/json', 'Accept': 'application/json'}

            # Add API key if available
            if self.api_key:
                headers['X-Api-Key'] = self.api_key

                # With API key, use full API endpoints
                await self._search_subdomains(headers)
                await self._search_dns_history(headers)
                await self._search_emails(headers)
            else:
                # Without API key, use the provider's limited endpoint only.
                logger.info('[*] Windvane API key not found. Using limited unauthenticated access.')
                await self._search_subdomains_limited(headers)

        except Exception as e:
            logger.info(f'Windvane API error: {e}')

    async def _search_subdomains(self, headers: dict) -> None:
        """Search for subdomains using /ListSubDomain endpoint"""
        try:
            url = f'{self.hostname}/ListSubDomain'

            # Use pagination to get more results
            for page in range(1, 4):  # Get first 3 pages (up to 90 results)
                data = {'domain': self.word, 'page_request': {'page': page, 'count': 30}}

                try:
                    response = await AsyncFetcher.post_fetch(url, headers=headers, data=json.dumps(data), proxy=self.proxy)
                    if response:
                        response_data = self._safe_parse_json(response)

                        # Check if response is successful
                        if response_data.get('code') == 0:
                            data_section = response_data.get('data', {})
                            subdomains = data_section.get('list', [])

                            if not subdomains:
                                break  # No more results

                            for item in subdomains:
                                if isinstance(item, dict):
                                    self._add_host(item.get('domain'))
                        else:
                            # API error - stop pagination
                            if response_data.get('code') != 0:
                                logger.info(f'Windvane subdomain API returned code {response_data.get("code")}')
                            break

                except Exception as e:
                    logger.info(f'Windvane subdomain request failed: {e}')
                    break

        except Exception as e:
            logger.info(f'Windvane subdomain search error: {e}')

    async def _search_dns_history(self, headers: dict) -> None:
        """Search DNS history using /ListDNS endpoint for additional subdomains and IPs"""
        try:
            url = f'{self.hostname}/ListDNS'

            # Get DNS history records
            for page in range(1, 3):  # Get first 2 pages
                data = {'domain': self.word, 'page_request': {'page': page, 'count': 30}}

                try:
                    response = await AsyncFetcher.post_fetch(url, headers=headers, data=json.dumps(data), proxy=self.proxy)
                    if response:
                        response_data = self._safe_parse_json(response)

                        if response_data.get('code') == 0:
                            data_section = response_data.get('data', {})
                            dns_records = data_section.get('list', [])

                            if not dns_records:
                                break

                            for record in dns_records:
                                if isinstance(record, dict):
                                    answer = record.get('answer', '')
                                    answer_type = record.get('answer_type', '')

                                    domain_is_scoped = self._add_host(record.get('domain'))

                                    # Add IP addresses from A records
                                    if domain_is_scoped and answer and answer_type == 'A' and self._is_valid_ip(answer):
                                        self.totalips.add(answer)
                        else:
                            break

                except Exception as e:
                    logger.info(f'Windvane DNS history request failed: {e}')
                    break

        except Exception as e:
            logger.info(f'Windvane DNS history search error: {e}')

    async def _search_emails(self, headers: dict) -> None:
        """Search for emails using /ListEmail endpoint"""
        try:
            url = f'{self.hostname}/ListEmail'

            data = {'email': self.word, 'page_request': {'page': 1, 'count': 50}}

            try:
                response = await AsyncFetcher.post_fetch(url, headers=headers, data=json.dumps(data), proxy=self.proxy)
                if response:
                    response_data = self._safe_parse_json(response)

                    if response_data.get('code') == 0:
                        data_section = response_data.get('data', {})
                        email_results = data_section.get('list', [])

                        for item in email_results:
                            if isinstance(item, dict):
                                self._add_email(item.get('email'))
                                self._add_host(item.get('domain'))

            except Exception as e:
                logger.info(f'Windvane email search request failed: {e}')

        except Exception as e:
            logger.info(f'Windvane email search error: {e}')

    async def _search_subdomains_limited(self, headers: dict) -> None:
        """Limited subdomain search without API key - tries simpler approaches"""
        try:
            # Try basic subdomain endpoint with minimal parameters
            url = f'{self.hostname}/ListSubDomain'

            # Simple request with just domain - limited to 5 calls
            data = {
                'domain': self.word,
                'page_request': {
                    'page': 1,
                    'count': 10,  # Smaller count for unauthenticated
                },
            }

            try:
                response = await AsyncFetcher.post_fetch(url, headers=headers, data=json.dumps(data), proxy=self.proxy)
                if response:
                    response_data = self._safe_parse_json(response)

                    if isinstance(response_data, dict) and response_data.get('code') == 0:
                        data_section = response_data.get('data', {})
                        subdomains = data_section.get('list', [])

                        for item in subdomains:
                            if isinstance(item, dict):
                                self._add_host(item.get('domain'))

                        logger.info(f'[*] Found {len(subdomains)} subdomains with limited access')
                    else:
                        logger.info(f'Windvane limited API returned code {response_data.get("code")}')

            except Exception as e:
                logger.info(f'Windvane limited API failed: {e}')

        except Exception as e:
            logger.info(f'Windvane limited search error: {e}')

    def set_api_key(self, api_key: str) -> None:
        """Set the API key for authenticated requests

        Args:
            api_key: Windvane API key for authenticated access

        """
        self.api_key = api_key

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate if string is a valid IP address"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, TypeError):
            return False

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def get_emails(self) -> set:
        return self.totalemails

    async def process(self, proxy: bool = False) -> None:
        """Process the search with optional proxy and API key configuration

        Args:
            proxy: Whether to use proxy for requests

        """
        self.proxy = proxy

        # API key is already set via _get_api_key() method

        await self.do_search()
