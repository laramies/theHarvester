import asyncio
import logging
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from aiohttp import ClientError

from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from aiohttp import ClientSession


class SearchHudsonRock:
    """Search Hudson Rock for compromised credentials and infostealer data.

    The adapter queries the Cavalier API for leaked credentials, compromised
    hosts, and infostealer records.
    """

    def __init__(self, word: str) -> None:
        """Configure a Hudson Rock search.

        Args:
            word: Domain or email address to search.

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

    def _has_results(self) -> bool:
        return bool(self.totalhosts or self.totalips or self.emails or self.infostealers)

    async def do_search(self, session: ClientSession) -> SourceExecutionReport | None:
        """Query by domain and, for email targets, by email address.

        Requests are retried when the provider rate limits them.
        """
        self.logger.info(f'Starting Hudson Rock search for: {self.word}')

        searches = []

        # Always search by domain (even for emails, to find related domains)
        domain_to_search = self.word if '@' not in self.word else self.word.split('@')[1]
        searches.append((self._search_domain, domain_to_search))

        # Search by email if the word looks like an email
        if '@' in self.word and self._is_valid_email(self.word):
            searches.append((self._search_email, self.word))

        # Execute searches with rate limiting
        reports: list[SourceExecutionReport] = []
        for index, (search, target) in enumerate(searches):
            try:
                if report := await search(target, session):
                    reports.append(report)
                if index < len(searches) - 1:
                    await asyncio.sleep(self.request_delay)
            except OSError, RuntimeError, ValueError:
                self.logger.error('Hudson Rock search task failed')
                reports.append(SourceExecutionReport('failed', 'transport-error'))

        self.logger.info(
            f'Hudson Rock search completed. Found {len(self.totalhosts)} hosts, '
            f'{len(self.totalips)} IPs, {len(self.emails)} emails'
        )
        if not reports:
            return None
        if len(reports) < len(searches) or self._has_results():
            return SourceExecutionReport('partial', reports[0].stop_reason)
        return reports[0]

    def _is_valid_email(self, email: str) -> bool:
        """Validate email format.

        Args:
            email: Email address to validate.

        Returns:
            Whether the email address matches the supported format.

        """
        import re

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    async def _search_domain(self, domain: str, session: ClientSession) -> SourceExecutionReport | None:
        """Search Hudson Rock by domain with retry logic.

        Args:
            domain: Domain to search.

        """
        url = f'{self.base_url}/search-by-domain?domain={domain}'
        response, report = await self._fetch_response(url, 'domain', domain, session)
        if report is not None:
            return report
        assert response is not None
        if self._process_domain_response(response):
            return SourceExecutionReport('partial' if self._has_results() else 'failed', 'invalid-response')
        return None

    async def _search_email(self, email: str, session: ClientSession) -> SourceExecutionReport | None:
        """Search Hudson Rock by email with retry logic.

        Args:
            email: Email address to search.

        """
        url = f'{self.base_url}/search-by-email?email={email}'
        response, report = await self._fetch_response(url, 'email', email, session)
        if report is not None:
            return report
        assert response is not None
        if self._process_email_response(response):
            return SourceExecutionReport('partial' if self._has_results() else 'failed', 'invalid-response')
        return None

    async def _fetch_response(
        self, url: str, search_type: str, target: str, session: ClientSession
    ) -> tuple[dict | None, SourceExecutionReport | None]:
        for attempt in range(self.max_retries):
            try:
                self.logger.debug(f'Searching {search_type}: {target} (attempt {attempt + 1})')
                responses = await AsyncFetcher.fetch_all([url], session=session, json=True, include_metadata=True)
                response = responses[0] if responses and isinstance(responses[0], FetcherResponse) else None
                if response is None:
                    self.logger.warning(f'Invalid response format for {search_type} search: {target}')
                    return None, SourceExecutionReport('failed', 'transport-error')
                if isinstance(response, FetcherResponse) and response.status == 429:
                    if attempt == self.max_retries - 1:
                        self.logger.info(f'Hudson Rock {search_type} search returned HTTP 429 after {self.max_retries} attempts')
                        return None, SourceExecutionReport('rate-limited', 'http-429')
                    retry_after = response.headers.get('retry-after')
                    try:
                        delay = int(retry_after) if retry_after is not None else 2**attempt
                    except ValueError:
                        delay = 2**attempt
                    await asyncio.sleep(max(0, min(delay, 60)))
                    continue
                if error := provider_http_error(response):
                    self.logger.info(f'Hudson Rock {search_type} search failed with HTTP {response.status}')
                    return None, SourceExecutionReport(*error)
                if not isinstance(response.body, dict):
                    self.logger.warning(f'Invalid response format for {search_type} search: {target}')
                    return None, SourceExecutionReport('failed', 'invalid-response')
                if response.body.get('error'):
                    self.logger.info(f'Hudson Rock {search_type} search returned a provider error')
                    return None, SourceExecutionReport('failed', 'provider-error')
                return response.body, None

            except OSError, RuntimeError, ValueError:
                self.logger.error(f'Hudson Rock {search_type} search attempt {attempt + 1} failed')
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2**attempt)
                else:
                    return None, SourceExecutionReport('failed', 'transport-error')
        return None, SourceExecutionReport('failed', 'transport-error')

    def _process_domain_response(self, response: dict) -> bool:
        """Process domain search response from Hudson Rock API.

        Args:
            response: Hudson Rock domain-search response.

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
            data = response.get('data')
            if not isinstance(data, dict):
                return True

            # Process employee URLs
            employees_urls = data.get('employees_urls', [])
            malformed = self._extract_hosts_from_urls(employees_urls, 'employee')

            # Process user URLs
            users_urls = data.get('users_urls', [])
            malformed |= self._extract_hosts_from_urls(users_urls, 'user')

            # Process third party URLs if available
            third_party_urls = data.get('third_parties_urls', [])
            malformed |= self._extract_hosts_from_urls(third_party_urls, 'third_party')

            # Extract emails from the data
            malformed |= self._extract_emails_from_data(data)
            return malformed

        except TypeError, ValueError:
            self.logger.error('Error processing Hudson Rock domain response')
            return True

    def _extract_hosts_from_urls(self, urls_data: list[dict], source_type: str) -> bool:
        """Extract hostnames from URL data.

        Args:
            urls_data: URL records.
            source_type: Source category: employee, user, or third party.

        """
        if not isinstance(urls_data, list):
            return True
        extracted_count = 0
        malformed = False

        for url_data in urls_data:
            if not isinstance(url_data, dict):
                malformed = True
                continue
            url = url_data.get('url', '')
            if not isinstance(url, str) or not url:
                malformed = True
                continue
            if url.startswith('https://•••') or url.startswith('http://•••'):
                continue

            try:
                parsed = urlparse(url)
                if parsed.hostname and parsed.hostname not in self.totalhosts:
                    self.totalhosts.add(parsed.hostname)
                    extracted_count += 1
                    self.logger.debug(f'Extracted {source_type} host: {parsed.hostname}')

            except ValueError:
                malformed = True
                self.logger.warning('Failed to parse Hudson Rock URL')

        if extracted_count > 0:
            self.logger.info(f'Extracted {extracted_count} hosts from {source_type} URLs')
        return malformed

    def _extract_emails_from_data(self, data: dict) -> bool:
        """Extract email addresses from response data.

        Args:
            data: Hudson Rock response data.

        """
        # Look for emails in various data fields
        email_fields = ['employees_emails', 'users_emails', 'emails']

        malformed = False
        for field in email_fields:
            if field in data:
                emails_data = data[field]
                if isinstance(emails_data, list):
                    for email_data in emails_data:
                        if isinstance(email_data, dict):
                            email = email_data.get('email', '')
                        else:
                            email = str(email_data)

                        if email and self._is_valid_email(email):
                            self.emails.add(email)
                            self.logger.debug(f'Extracted email: {email}')
                        elif email:
                            malformed = True
                else:
                    malformed = True
        return malformed

    def _process_email_response(self, response: dict) -> bool:
        """Process email search response from Hudson Rock API.

        Args:
            response: Hudson Rock email-search response.

        """
        try:
            # Process stealer data with enhanced information extraction
            stealers = response.get('stealers')
            if not isinstance(stealers, list):
                return True
            self.logger.info(f'Processing {len(stealers)} stealer records for email: {self.word}')

            malformed = False
            for stealer in stealers:
                if not isinstance(stealer, dict):
                    malformed = True
                    continue
                corporate_services = stealer.get('top_corporate_services', [])
                user_services = stealer.get('top_user_services', [])
                if not isinstance(corporate_services, list) or not isinstance(user_services, list):
                    malformed = True
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
                    'top_corporate_services': corporate_services,
                    'top_user_services': user_services,
                }

                # Extract and validate IP addresses
                ip = stealer.get('ip', '')
                if ip and self._is_valid_ip(ip):
                    self.totalips.add(ip)
                    self.logger.debug(f'Extracted IP: {ip}')

                # Extract hostnames from services
                self._extract_hosts_from_services(corporate_services)
                self._extract_hosts_from_services(user_services)

                self.infostealers.append(stealer_info)

            self.logger.info(f'Processed {len(stealers)} stealer records, extracted {len(self.totalips)} IPs')
            return malformed

        except TypeError, ValueError:
            self.logger.error('Error processing Hudson Rock email response')
            return True

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format.

        Args:
            ip: IP address to validate.

        Returns:
            Whether the value is a supported IPv4 address.

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
            services: Service records.

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

                            except TypeError, ValueError:
                                self.logger.warning('Failed to parse Hudson Rock service URL')

    async def get_hostnames(self) -> set[str]:
        """Return discovered hostnames.

        Returns:
            Unique hostnames found in Hudson Rock data.

        """
        return self.totalhosts

    async def get_ips(self) -> set[str]:
        """Return discovered IP addresses.

        Returns:
            Unique IP addresses found in Hudson Rock data.

        """
        return self.totalips

    async def get_emails(self) -> set[str]:
        """Return discovered email addresses.

        Returns:
            Unique email addresses found in Hudson Rock data.

        """
        return self.emails

    async def get_infostealers(self) -> list[dict]:
        """Return infostealer intelligence data.

        Returns:
            Infostealer records.

        """
        return self.infostealers

    async def get_compromised_data(self) -> dict:
        """Return compromised data statistics.

        Returns:
            Compromised-data counts.

        """
        return self.compromised_data

    def get_summary(self) -> dict:
        """Get a summary of all discovered data.

        Returns:
            Counts for the collected result types.

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

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        """Run the Hudson Rock search.

        Args:
            proxy: Whether to use a proxy for requests.

        """
        self.proxy = proxy
        self.logger.info(f'Starting Hudson Rock processing for: {self.word}')

        try:
            async with AsyncFetcher.open_session(proxy=self.proxy, request_timeout=60) as session:
                report = await self.do_search(session)
            summary = self.get_summary()
            self.logger.info(
                f'Hudson Rock processing completed successfully: '
                f'{summary["total_hosts"]} hosts, {summary["total_ips"]} IPs, '
                f'{summary["total_emails"]} emails, {summary["total_stealers"]} stealers'
            )
            return report
        except ResponseStreamError as error:
            return SourceExecutionReport('failed', error.reason)
        except ClientError, OSError:
            self.logger.error('Hudson Rock processing failed')
            return SourceExecutionReport('failed', 'transport-error')
