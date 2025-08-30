import asyncio
from typing import Any

from theHarvester.discovery.builtwith import SearchBuiltWith
from theHarvester.discovery.haveibeenpwned import SearchHaveIBeenPwned
from theHarvester.discovery.leaklookup import SearchLeakLookup
from theHarvester.discovery.securityscorecard import SearchSecurityScorecard
from theHarvester.discovery.shodansearch import SearchShodan


class AdditionalAPIs:
    """Wrapper class for additional API services."""

    def __init__(self, domain: str, api_keys: dict[str, str] | None = None):
        self.domain = domain
        self.api_keys = api_keys or {}

        # Initialize API services
        self.haveibeenpwned = SearchHaveIBeenPwned(domain)
        self.leaklookup = SearchLeakLookup(domain)
        self.securityscorecard = SearchSecurityScorecard(domain)
        self.builtwith = SearchBuiltWith(domain)
        self.shodan: SearchShodan | None = None  # Will be initialized when needed

        # Aggregated sets for results
        self.hosts: set[str] = set()
        self.emails: set[str] = set()

        # Results storage
        self.results: dict[str, Any] = {
            'breaches': [],
            'leaks': [],
            'security_score': {},
            'tech_stack': {},
            'shodan_data': {},
            'hosts': [],
            'emails': [],
        }
        self.shodan_data: dict[str, Any] = {}

    async def process(self, proxy: bool = False) -> dict[str, Any]:
        """Process all additional API services and return combined results."""
        tasks = [
            self._process_haveibeenpwned(proxy),
            self._process_leaklookup(proxy),
            self._process_securityscorecard(proxy),
            self._process_builtwith(proxy),
            self._process_shodan(proxy),
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

        # Convert aggregated sets to lists for JSON serialization
        self.results['hosts'] = list(self.hosts)
        self.results['emails'] = list(self.emails)
        self.results['shodan_data'] = self.shodan_data

        return self.results

    async def _process_haveibeenpwned(self, proxy: bool = False):
        """Process HaveIBeenPwned API."""
        try:
            await self.haveibeenpwned.process(proxy)
            self.results['breaches'] = self.haveibeenpwned.breaches
            self.hosts.update(self.haveibeenpwned.hosts)
            self.emails.update(self.haveibeenpwned.emails)
        except Exception as e:
            print(f'Error processing HaveIBeenPwned: {e}')

    async def _process_leaklookup(self, proxy: bool = False):
        """Process Leak-Lookup API."""
        try:
            await self.leaklookup.process(proxy)
            self.results['leaks'] = self.leaklookup.leaks
            self.hosts.update(self.leaklookup.hosts)
            self.emails.update(self.leaklookup.emails)
        except Exception as e:
            print(f'Error processing Leak-Lookup: {e}')

    async def _process_securityscorecard(self, proxy: bool = False):
        """Process SecurityScorecard API."""
        try:
            await self.securityscorecard.process(proxy)
            self.results['security_score'] = {
                'score': self.securityscorecard.score,
                'grades': self.securityscorecard.grades,
                'issues': self.securityscorecard.issues,
                'recommendations': self.securityscorecard.recommendations,
            }
            self.hosts.update(self.securityscorecard.hosts)
        except Exception as e:
            print(f'Error processing SecurityScorecard: {e}')

    async def _process_builtwith(self, proxy: bool = False):
        """Process BuiltWith API."""
        try:
            await self.builtwith.process(proxy)
            self.results['tech_stack'] = {
                'frameworks': list(self.builtwith.frameworks),
                'languages': list(self.builtwith.languages),
                'servers': list(self.builtwith.servers),
                'cms': list(self.builtwith.cms),
                'analytics': list(self.builtwith.analytics),
                'interesting_urls': list(self.builtwith.interesting_urls),
            }
            self.hosts.update(self.builtwith.hosts)
        except Exception as e:
            print(f'Error processing BuiltWith: {e}')

    async def _process_shodan(self, proxy: bool = False):
        """Process Shodan API for IP information."""
        try:
            # Initialize Shodan only when needed
            if self.shodan is None:
                self.shodan = SearchShodan()

            # Get IPs from hosts for Shodan lookup
            import socket

            ips_to_search: set[str] = set()

            # Try to resolve domain to IP
            try:
                ip = socket.gethostbyname(self.domain)
                ips_to_search.add(ip)
            except socket.gaierror as e:
                print(f"Failed to resolve domain '{self.domain}': {e}")
            except Exception as e:
                print(f"Unexpected error while resolving domain '{self.domain}': {e}")

            # Add any IPs from other results
            for host in self.hosts:
                if ':' in host:
                    # Extract IP from host:ip format
                    parts = host.split(':')
                    if len(parts) == 2 and self._is_valid_ip(parts[1]):
                        ips_to_search.add(parts[1])
                elif self._is_valid_ip(host):
                    ips_to_search.add(host)

            # Search each IP in Shodan
            for ip in ips_to_search:
                try:
                    print(f'\tSearching Shodan for {ip}')
                    shodan_result = await self.shodan.search_ip(ip)

                    if ip in shodan_result and isinstance(shodan_result[ip], dict):
                        self.shodan_data[ip] = shodan_result[ip]
                    elif ip in shodan_result and isinstance(shodan_result[ip], str):
                        print(f'{ip}: {shodan_result[ip]}')

                    await asyncio.sleep(2)  # Rate limiting
                except Exception as ip_error:
                    print(f'Error searching Shodan for {ip}: {ip_error}')
                    continue

        except Exception as e:
            print(f'Error processing Shodan: {e}')

    @staticmethod
    def _is_valid_ip(ip_str: str) -> bool:
        """Check if a string is a valid IP address."""
        import ipaddress

        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    async def get_hosts(self) -> set[str]:
        """Get all discovered hosts."""
        return self.hosts

    async def get_emails(self) -> set[str]:
        """Get all discovered emails."""
        return self.emails
