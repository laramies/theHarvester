import asyncio
import logging
from urllib.parse import urlparse

from theHarvester.lib.core import AsyncFetcher, FetcherResponse


class SearchHudsonRock:
    """Hudson Rock API integration for discovering compromised credentials and stealer logs.

    This class provides comprehensive search capabilities using Hudson Rock's Cavalier API
    to discover leaked credentials, compromised hosts, and infostealer intelligence.
    """

    def __init__(self, word: str) -> None:
        """Initialize Hudson Rock search.

        Args:
            word: Domain or email to search for

        """
        self.word = word.strip().lower()
        self.base_url = 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools'
        self.totalhosts: set[str] = set()
        self.totalips: set[str] = set()
        self.emails: set[str] = set()
        self.infostealers: list[dict] = []
        self.compromised_data: dict = {}
        self.proxy = False
        self.logger = logging.getLogger(__name__)

        # Rate limiting
        self.request_delay = 1.0  # Delay between requests in seconds
        self.max_retries = 3

    async def do_search(self) -> None:
        """Search Hudson Rock for infostealer intelligence data.

        Performs comprehensive search using both domain and email endpoints
        with proper error handling and rate limiting.
        """
        self.logger.info(f'Starting Hudson Rock search for: {self.word}')

        search_tasks = []

        # Always search by domain (even for emails, to find related domains)
        domain_to_search = self.word if '@' not in self.word else self.word.split('@')[1]
        search_tasks.append(self._search_domain(domain_to_search))

        # Search by email if the word looks like an email
        if '@' in self.word and self._is_valid_email(self.word):
            search_tasks.append(self._search_email(self.word))

        # Execute searches with rate limiting
        for index, task in enumerate(search_tasks):
            try:
                await task
                if index < len(search_tasks) - 1:
                    await asyncio.sleep(self.request_delay)
            except Exception as e:
                self.logger.error(f'Search task failed: {e}')
                continue

        self.logger.info(
            f'Hudson Rock search completed. Found {len(self.totalhosts)} hosts, '
            f'{len(self.totalips)} IPs, {len(self.emails)} emails'
        )

    def _is_valid_email(self, email: str) -> bool:
        """Validate email format.

        Args:
            email: Email address to validate

        Returns:
            True if email format is valid

        """
        import re

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    async def _search_domain(self, domain: str) -> None:
        """Search Hudson Rock by domain with retry logic.

        Args:
            domain: Domain to search for

        """
        url = f'{self.base_url}/search-by-domain?domain={domain}'
        response = await self._fetch_response(url, 'domain', domain)
        if response is not None:
            self._process_domain_response(response)

    async def _search_email(self, email: str) -> None:
        """Search Hudson Rock by email with retry logic.

        Args:
            email: Email address to search for

        """
        url = f'{self.base_url}/search-by-email?email={email}'
        response = await self._fetch_response(url, 'email', email)
        if response is not None:
            self._process_email_response(response)

    async def _fetch_response(self, url: str, search_type: str, target: str) -> dict | None:
        for attempt in range(self.max_retries):
            try:
                self.logger.debug(f'Searching {search_type}: {target} (attempt {attempt + 1})')
                responses = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy, include_metadata=True)
                response = responses[0] if responses and isinstance(responses[0], FetcherResponse) else None
                if response is None:
                    self.logger.warning(f'Invalid response format for {search_type} search: {target}')
                    return None
                if response.status == 429:
                    if attempt == self.max_retries - 1:
                        self.logger.info(f'Hudson Rock {search_type} search returned HTTP 429 after {self.max_retries} attempts')
                        return None
                    retry_after = response.headers.get('retry-after')
                    try:
                        delay = int(retry_after) if retry_after is not None else 2**attempt
                    except ValueError:
                        delay = 2**attempt
                    await asyncio.sleep(max(0, min(delay, 60)))
                    continue
                if not 200 <= response.status < 300:
                    self.logger.info(f'Hudson Rock {search_type} search failed with HTTP {response.status}')
                    return None
                if not isinstance(response.body, dict):
                    self.logger.warning(f'Invalid response format for {search_type} search: {target}')
                    return None
                return response.body

            except Exception as e:
                self.logger.error(f'{search_type.title()} search attempt {attempt + 1} failed for {target}: {e}')
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2**attempt)
                else:
                    raise
        return None

    def _process_domain_response(self, response: dict) -> None:
        """Process domain search response from Hudson Rock API.

        Args:
            response: JSON response from Hudson Rock domain search API

        """
        try:
            # Store overall statistics
            stats = {
                'total_compromised': response.get('total', 0),
                'employees': response.get('employees', 0),
                'users': response.get('users', 0),
                'third_parties': response.get('third_parties', 0),
                'domain': self.word,
            }
            self.compromised_data.update(stats)

            self.logger.info(
                f'Domain statistics: {stats["total_compromised"]} total compromised, '
                f'{stats["employees"]} employees, {stats["users"]} users'
            )

            # Extract URLs and hosts from response data
            data = response.get('data', {})

            # Process employee URLs
            employees_urls = data.get('employees_urls', [])
            self._extract_hosts_from_urls(employees_urls, 'employee')

            # Process user URLs
            users_urls = data.get('users_urls', [])
            self._extract_hosts_from_urls(users_urls, 'user')

            # Process third party URLs if available
            third_party_urls = data.get('third_parties_urls', [])
            self._extract_hosts_from_urls(third_party_urls, 'third_party')

            # Extract emails from the data
            self._extract_emails_from_data(data)

        except Exception as e:
            self.logger.error(f'Error processing Hudson Rock domain response: {e}', exc_info=True)

    def _extract_hosts_from_urls(self, urls_data: list[dict], source_type: str) -> None:
        """Extract hostnames from URL data.

        Args:
            urls_data: List of URL data dictionaries
            source_type: Type of source (employee, user, third_party)

        """
        extracted_count = 0

        for url_data in urls_data:
            if not isinstance(url_data, dict):
                continue
            url = url_data.get('url', '')
            if not url or url.startswith('https://•••') or url.startswith('http://•••'):
                continue

            try:
                parsed = urlparse(url)
                if parsed.hostname and parsed.hostname not in self.totalhosts:
                    self.totalhosts.add(parsed.hostname)
                    extracted_count += 1
                    self.logger.debug(f'Extracted {source_type} host: {parsed.hostname}')

            except Exception as e:
                self.logger.warning(f'Failed to parse URL {url}: {e}')

        if extracted_count > 0:
            self.logger.info(f'Extracted {extracted_count} hosts from {source_type} URLs')

    def _extract_emails_from_data(self, data: dict) -> None:
        """Extract email addresses from response data.

        Args:
            data: Response data dictionary

        """
        # Look for emails in various data fields
        email_fields = ['employees_emails', 'users_emails', 'emails']

        for field in email_fields:
            if field in data:
                emails_data = data[field]
                if isinstance(emails_data, list):
                    for email_data in emails_data:
                        if isinstance(email_data, dict):
                            email = email_data.get('email', '')
                        else:
                            email = str(email_data)

                        if email and self._is_valid_email(email) and email not in self.emails:
                            self.emails.add(email)
                            self.logger.debug(f'Extracted email: {email}')

    def _process_email_response(self, response: dict) -> None:
        """Process email search response from Hudson Rock API.

        Args:
            response: JSON response from Hudson Rock email search API

        """
        try:
            # Process stealer data with enhanced information extraction
            stealers = response.get('stealers', [])
            self.logger.info(f'Processing {len(stealers)} stealer records for email: {self.word}')

            for stealer in stealers:
                if not isinstance(stealer, dict):
                    continue
                self.emails.add(self.word)
                stealer_info = {
                    'email': self.word,
                    'date_compromised': stealer.get('date_compromised'),
                    'computer_name': stealer.get('computer_name'),
                    'operating_system': stealer.get('operating_system'),
                    'malware_path': stealer.get('malware_path'),
                    'ip': stealer.get('ip'),
                    'total_corporate_services': stealer.get('total_corporate_services', 0),
                    'total_user_services': stealer.get('total_user_services', 0),
                    'antiviruses': stealer.get('antiviruses', []),
                    'top_corporate_services': stealer.get('top_corporate_services', []),
                    'top_user_services': stealer.get('top_user_services', []),
                }

                # Extract and validate IP addresses
                ip = stealer.get('ip', '')
                if ip and self._is_valid_ip(ip):
                    self.totalips.add(ip)
                    self.logger.debug(f'Extracted IP: {ip}')

                # Extract hostnames from services
                self._extract_hosts_from_services(stealer.get('top_corporate_services', []))
                self._extract_hosts_from_services(stealer.get('top_user_services', []))

                self.infostealers.append(stealer_info)

            self.logger.info(f'Processed {len(stealers)} stealer records, extracted {len(self.totalips)} IPs')

        except Exception as e:
            self.logger.error(f'Error processing Hudson Rock email response: {e}', exc_info=True)

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format.

        Args:
            ip: IP address to validate

        Returns:
            True if IP format is valid

        """
        if not ip or '*' in ip or '•' in ip:
            return False

        import ipaddress

        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _extract_hosts_from_services(self, services: list[dict]) -> None:
        """Extract hostnames from service data.

        Args:
            services: List of service dictionaries

        """
        for service in services:
            if isinstance(service, dict):
                # Look for URL or domain fields
                for field in ['url', 'domain', 'service_url', 'website']:
                    if field in service:
                        url = service[field]
                        if url and isinstance(url, str):
                            try:
                                # Handle both URLs and plain domains
                                if not url.startswith(('http://', 'https://')):
                                    url = f'https://{url}'

                                parsed = urlparse(url)
                                if parsed.hostname and parsed.hostname not in self.totalhosts:
                                    self.totalhosts.add(parsed.hostname)
                                    self.logger.debug(f'Extracted service host: {parsed.hostname}')

                            except Exception as e:
                                self.logger.warning(f'Failed to parse service URL {url}: {e}')

    async def get_hostnames(self) -> set[str]:
        """Return discovered hostnames.

        Returns:
            Set of unique hostnames discovered from Hudson Rock data

        """
        return self.totalhosts

    async def get_ips(self) -> set[str]:
        """Return discovered IP addresses.

        Returns:
            Set of unique IP addresses discovered from Hudson Rock data

        """
        return self.totalips

    async def get_emails(self) -> set[str]:
        """Return discovered email addresses.

        Returns:
            Set of unique email addresses discovered from Hudson Rock data

        """
        return self.emails

    async def get_infostealers(self) -> list[dict]:
        """Return infostealer intelligence data.

        Returns:
            List of dictionaries containing detailed stealer information

        """
        return self.infostealers

    async def get_compromised_data(self) -> dict:
        """Return compromised data statistics.

        Returns:
            Dictionary containing statistics about compromised data

        """
        return self.compromised_data

    def get_summary(self) -> dict:
        """Get a summary of all discovered data.

        Returns:
            Dictionary containing summary statistics

        """
        return {
            'search_target': self.word,
            'total_hosts': len(self.totalhosts),
            'total_ips': len(self.totalips),
            'total_emails': len(self.emails),
            'total_stealers': len(self.infostealers),
            'compromised_stats': self.compromised_data,
            'hosts': sorted(list(self.totalhosts)),
            'ips': sorted(list(self.totalips)),
            'emails': sorted(list(self.emails)),
        }

    async def process(self, proxy: bool = False) -> None:
        """Main processing method.

        Args:
            proxy: Whether to use proxy for requests

        """
        self.proxy = proxy
        self.logger.info(f'Starting Hudson Rock processing for: {self.word}')

        try:
            await self.do_search()
            summary = self.get_summary()
            self.logger.info(
                f'Hudson Rock processing completed successfully: '
                f'{summary["total_hosts"]} hosts, {summary["total_ips"]} IPs, '
                f'{summary["total_emails"]} emails, {summary["total_stealers"]} stealers'
            )
        except Exception as e:
            self.logger.error(f'Hudson Rock processing failed: {e}', exc_info=True)
            raise
