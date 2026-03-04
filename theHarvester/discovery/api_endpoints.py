"""
API endpoint scanner module.
This module contains the SearchApiEndpoints class that performs comprehensive API endpoint
scanning, detection, and analysis on target domains with advanced features for security testing.
"""

import asyncio
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

import aiohttp

from theHarvester.lib.core import AsyncFetcher, Core

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('api_endpoints')


@dataclass
class EndpointResult:
    """Data class for storing endpoint scan results."""

    url: str
    status_code: int = 0
    method: str = ''
    content_type: str = ''
    content_length: int = 0
    response_time: float = 0.0
    auth_required: bool = False
    api_version: str = ''
    rate_limited: bool = False
    rate_limit_headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, str] = field(default_factory=dict)
    content_preview: str = ''
    interesting: bool = False
    tech_stack: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class SearchApiEndpoints:
    """
    SearchApiEndpoints class for scanning common API endpoints on target domains.
    """

    def __init__(
        self,
        word: str,
        wordlist: str | None = None,
        concurrency: int = 20,
        timeout: int = 10,
        proxy: str | None = None,
        user_agent: str | None = None,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        additional_headers: dict[str, str] | None = None,
    ) -> None:
        """
        Initialize the SearchApiEndpoints class with advanced configuration options.

        Args:
            word: The target domain to scan
            wordlist: Optional path to a custom wordlist file
            concurrency: Maximum number of concurrent requests (default: 20)
            timeout: Request timeout in seconds (default: 10)
            proxy: Proxy URL (e.g. "http://127.0.0.1:8080")
            user_agent: Custom User-Agent string
            follow_redirects: Whether to follow HTTP redirects
            verify_ssl: Whether to verify SSL certificates
            additional_headers: Additional HTTP headers to include in requests
        """
        self.word = word
        self.hosts: set[str] = set()
        self.endpoints: set[str] = set()
        self.found_endpoints: dict[str, EndpointResult] = {}
        self.interesting_endpoints: dict[str, EndpointResult] = {}
        self.auth_required: dict[str, EndpointResult] = {}
        self.api_versions: set[str] = set()
        self.rate_limits: dict[str, EndpointResult] = {}
        self.methods: set[str] = set()
        self.status_codes: set[int] = set()
        self.response_sizes: dict[str, int] = {}
        self.tech_stack: dict[str, list[str]] = {}
        self.schema_detected: dict[str, dict[str, Any]] = {}
        self.proxy = proxy
        self.concurrency = concurrency
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.semaphore = asyncio.Semaphore(concurrency)
        self.user_agent = user_agent or Core.get_user_agent()
        self.additional_headers = additional_headers or {}

        # Set default wordlist path
        default_wordlist = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'wordlists', 'api_endpoints.txt'
        )
        self.wordlist = wordlist if wordlist else default_wordlist

        # Add comprehensive API paths categorized by functionality
        self.common_api_paths = [
            # Core API endpoints
            '/api',
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/api/latest',
            '/api/beta',
            '/rest',
            '/rest/v1',
            '/rest/v2',
            '/rest/api',
            '/restapi',
            '/api/rest',
            '/service',
            '/services',
            '/service-api',
            '/api-service',
            '/api-gateway',
            '/gateway',
            '/api-proxy',
            '/apis',
            # GraphQL endpoints
            '/graphql',
            '/gql',
            '/graph',
            '/graphiql',
            '/graphql-api',
            '/graphql/console',
            '/graphql-console',
            '/graphql-playground',
            '/graphql-explorer',
            '/graphql/explorer',
            # API documentation
            '/swagger',
            '/swagger-ui',
            '/swagger-ui.html',
            '/swagger-resources',
            '/swagger.json',
            '/swagger.yaml',
            '/swagger-config',
            '/api-docs',
            '/api-docs.json',
            '/api/swagger',
            '/api/docs',
            '/docs/api',
            '/documentation',
            '/openapi',
            '/openapi.json',
            '/openapi.yaml',
            '/docs',
            '/redoc',
            '/apidoc',
            '/schema',
            '/api-explorer',
            '/api-reference',
            # API versions and versioning
            '/v1',
            '/v2',
            '/v3',
            '/v4',
            '/v5',
            '/v1.0',
            '/v2.0',
            '/v3.0',
            '/version',
            '/versions',
            '/api/versions',
            '/api-version',
            # Authentication and authorization
            '/auth',
            '/oauth',
            '/oauth2',
            '/oauth/token',
            '/oauth/authorize',
            '/identity',
            '/login',
            '/signin',
            '/signup',
            '/register',
            '/token',
            '/jwt',
            '/auth/token',
            '/api/auth',
            '/api/login',
            '/api/logout',
            '/oidc',
            '/connect/token',
            '/connect/authorize',
            '/api/access-token',
            '/auth/refresh',
            '/2fa',
            '/mfa',
            '/api/authenticate',
            '/sso',
            # User management
            '/users',
            '/api/users',
            '/accounts',
            '/api/accounts',
            '/profiles',
            '/api/profiles',
            '/members',
            '/api/members',
            '/api/me',
            '/api/user',
            # System status and monitoring
            '/health',
            '/healthcheck',
            '/health-check',
            '/status',
            '/api/status',
            '/metrics',
            '/prometheus',
            '/monitoring',
            '/stats',
            '/statistics',
            '/ping',
            '/alive',
            '/readiness',
            '/liveness',
            '/heartbeat',
            # Data operations
            '/data',
            '/database',
            '/query',
            '/search',
            '/api/search',
            '/filter',
            '/api/data',
            '/export',
            '/import',
            '/backup',
            '/restore',
            # Admin interfaces
            '/admin',
            '/admin/api',
            '/management',
            '/manage',
            '/console',
            '/dashboard',
            '/control',
            '/panel',
            '/administrator',
            '/sys',
            # Common application endpoints
            '/app',
            '/application',
            '/mobile-api',
            '/web-api',
            '/public-api',
            '/internal-api',
            '/private-api',
            '/external-api',
            '/partner-api',
            # File operations
            '/files',
            '/api/files',
            '/upload',
            '/api/upload',
            '/download',
            '/media',
            '/images',
            '/documents',
            '/attachments',
            '/assets',
            # Webhooks and integrations
            '/webhooks',
            '/hooks',
            '/callback',
            '/integration',
            '/integrations',
            '/api/webhooks',
            '/events',
            '/notifications',
            '/feeds',
            '/subscriptions',
            # General functionality
            '/config',
            '/settings',
            '/preferences',
            '/options',
            '/system',
            '/info',
            '/about',
            '/help',
            '/support',
            '/contact',
            # Legacy and common paths
            '/api.php',
            '/api.asp',
            '/api.jsp',
            '/api.do',
            '/api.json',
            '/api.xml',
            '/rpc',
            '/soap',
            '/ws',
            '/webservice',
            '/jsonrpc',
            '/api/soap',
            '/soap/api',
            '/xml-rpc',
            '/wsdl',
            '/asmx',
            # eCommerce specific
            '/products',
            '/orders',
            '/cart',
            '/checkout',
            '/payment',
            '/catalog',
            '/inventory',
            '/api/products',
            '/api/orders',
            # Content management
            '/content',
            '/posts',
            '/articles',
            '/pages',
            '/comments',
            '/tags',
            '/categories',
            '/api/content',
            '/api/posts',
            # Analytics and reporting
            '/analytics',
            '/reports',
            '/reporting',
            '/logs',
            '/audit',
            '/tracking',
            '/api/reports',
            '/api/analytics',
            '/api/logs',
            # Third-party API patterns
            '/api/facebook',
            '/api/google',
            '/api/twitter',
            '/api/github',
            '/api/stripe',
            '/api/paypal',
            '/api/aws',
            '/api/azure',
            # Mobile app specific
            '/mobile',
            '/app/api',
            '/api/mobile',
            '/api/app',
            '/api/ios',
            '/api/android',
            # Common test endpoints
            '/test',
            '/demo',
            '/sample',
            '/example',
            '/sandbox',
            '/dev',
            '/staging',
            '/beta',
            '/alpha',
            '/development',
            '/testing',
        ]

        # Patterns for identifying API technologies
        self.tech_patterns = {
            'graphql': [r'{"data":', r'"errors":', r'"query":', r'graphql'],
            'swagger': [r'swagger', r'openapi', r'api-docs'],
            'oauth': [r'oauth', r'token', r'authorize', r'access_token'],
            'jwt': [r'jwt', r'bearer', r'authorization'],
            'rest': [r'rest', r'/v\d+/', r'application/json'],
            'soap': [r'soap', r'xml', r'wsdl', r'xmlns'],
            'grpc': [r'grpc', r'protocol-buffers'],
        }

        # Initialize results storage
        self.results: list[EndpointResult] = []

        # Logger setup
        self.logger = logger

    async def do_search(self) -> None:
        """
        Perform the API endpoint scan with advanced features.
        """
        try:
            self.logger.info(f'Starting API endpoint scan for {self.word}')

            # Load endpoints from wordlist
            endpoints = self._load_wordlist()
            if not endpoints:
                self.logger.warning(f'No endpoints found in wordlist: {self.wordlist}')
                endpoints = []

            # Add common API paths that might not be in the wordlist
            endpoints.extend(self.common_api_paths)
            endpoints = list(set(endpoints))  # Remove duplicates

            # Detect base URL schema (http or https)
            schema = await self._detect_schema()
            self.logger.info(f'Detected schema for {self.word}: {schema}')

            # Generate batches of tasks to control concurrency
            self.logger.info(f'Prepared {len(endpoints)} endpoints to scan with concurrency {self.concurrency}')

            # Create tasks with semaphore for controlled concurrency
            tasks = []
            for endpoint in endpoints:
                url = f'{schema}://{self.word}{endpoint}'
                tasks.append(self._check_endpoint_with_semaphore(url))

            # Execute tasks with progress tracking
            results = await asyncio.gather(*tasks)
            self.results = [r for r in results if r]

            self.logger.info(f'API endpoint scan completed. Found {len(self.found_endpoints)} endpoints.')

            # Additional processing after scan
            await self._post_scan_analysis()

        except Exception as e:
            self.logger.error(f'Error in API endpoint scan: {e!s}', exc_info=True)

    async def _detect_schema(self) -> str:
        """Detect if the domain supports HTTPS or fall back to HTTP."""
        try:
            https_url = f'https://{self.word}'
            headers = self._get_headers()

            response = await AsyncFetcher.fetch(
                url=https_url, headers=headers, proxy=self.proxy, verify=self.verify_ssl, request_timeout=self.timeout
            )

            if response and getattr(response, 'status', 0) < 400:
                return 'https'
            else:
                self.logger.info(f'[*] HTTPS request to {https_url} returned status: {getattr(response, "status", "No status")}')
        except (aiohttp.ClientError, TimeoutError, OSError, TypeError, ValueError, AttributeError) as e:
            self.logger.error(f"Failed to fetch HTTPS URL '{https_url}': {e}")

        return 'http'  # Fallback to HTTP if HTTPS fails

    async def _check_endpoint_with_semaphore(self, url: str) -> EndpointResult | None:
        """Execute endpoint check with semaphore for controlled concurrency."""
        async with self.semaphore:
            return await self._check_endpoint(url)

    def _load_wordlist(self) -> list[str]:
        """Load endpoints from wordlist file with advanced filtering."""
        try:
            with open(self.wordlist) as f:
                lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

            # Ensure all paths start with /
            endpoints = [line if line.startswith('/') else f'/{line}' for line in lines]

            # Add some path variations (with and without trailing slash)
            variations = []
            for endpoint in endpoints:
                variations.append(endpoint)
                if endpoint.endswith('/'):
                    variations.append(endpoint[:-1])  # Without trailing slash
                else:
                    variations.append(f'{endpoint}/')  # With trailing slash

            return list(set(variations))  # Return unique endpoints

        except OSError as e:
            self.logger.error(f'Error loading wordlist {self.wordlist}: {e}')
            return []

    async def _check_endpoint(self, url: str) -> EndpointResult | None:
        """
        Check if an endpoint exists and analyze its properties.

        Args:
            url: The URL to check.

        Returns:
            Optional[EndpointResult]: Result object or None if not found
        """
        methods = ['GET', 'POST', 'OPTIONS', 'HEAD', 'PUT', 'DELETE', 'PATCH']
        headers = self._get_headers()

        for method in methods:
            try:
                # Track request time
                start_time = asyncio.get_event_loop().time()

                # Use AsyncFetcher to make the request
                response = await AsyncFetcher.fetch(
                    url=url,
                    method=method,
                    headers=headers,
                    proxy=self.proxy,
                    verify=self.verify_ssl,
                    follow_redirects=self.follow_redirects,
                    request_timeout=self.timeout,
                )

                # Calculate response time
                response_time = asyncio.get_event_loop().time() - start_time

                # If we get a response, process it
                if response:
                    result = self._process_response(url, method, response, response_time)
                    if result:
                        return result

            except TimeoutError:
                self.logger.debug(f'Timeout for {method} {url}')
                continue
            except (aiohttp.ClientError, OSError, TypeError, ValueError, AttributeError) as e:
                self.logger.debug(f'Error checking {method} {url}: {e!s}')
                continue

        return None

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with optional custom additions."""
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
        }

        # Add custom headers if provided
        if self.additional_headers:
            headers.update(self.additional_headers)

        return headers

    def _process_response(self, url: str, method: str, response, response_time: float) -> EndpointResult | None:
        """
        Process and categorize API endpoint response with detailed analysis.

        Returns:
            Optional[EndpointResult]: Result object or None if not relevant
        """
        status = getattr(response, 'status', 0)
        if status == 0:
            self.logger.warning(f'No status code received from response for URL: {url}')
            return None

        # Track this endpoint
        self.endpoints.add(url)
        self.methods.add(method)
        self.status_codes.add(status)

        # Get response headers safely
        try:
            headers = dict(getattr(response, 'headers', {}))
        except (TypeError, ValueError, AttributeError) as e:
            self.logger.error(f'Failed to get headers from response for URL {url}: {e}')
            headers = {}

        try:
            content = getattr(response, 'content', b'')
        except (TypeError, AttributeError) as e:
            self.logger.error(f'Failed to get content from response for URL {url}: {e}')
            content = b''

        content_length = len(content)
        self.response_sizes[url] = content_length

        # Try to get content type from headers
        content_type = headers.get('Content-Type', '')

        # Try to create a preview of the response content (up to 200 characters)
        content_preview = ''
        if content:
            try:
                content_preview = content.decode('utf-8', errors='ignore')[:200]
            except (AttributeError, UnicodeDecodeError) as e:
                self.logger.error(f'Failed to decode content for URL {url}: {e}')

        # Extract security headers
        security_headers = {
            k: v
            for k, v in headers.items()
            if k.lower()
            in [
                'content-security-policy',
                'x-xss-protection',
                'x-content-type-options',
                'strict-transport-security',
                'x-frame-options',
                'referrer-policy',
            ]
        }

        # Detect API version
        api_version = ''
        if '/v' in url:
            version_match = re.search(r'/v(\d+(?:\.\d+)*)', url)
            if version_match:
                api_version = f'v{version_match.group(1)}'
                self.api_versions.add(api_version)

        # Check if rate limited
        rate_limited = status == 429
        rate_limit_headers = {}
        if any(header.lower().startswith('x-rate-limit') or header.lower().startswith('ratelimit') for header in headers):
            rate_limit_headers = {k: v for k, v in headers.items() if 'rate' in k.lower() or 'limit' in k.lower()}

        # Determine if authentication is required
        auth_required = status in [401, 403]

        # Check if this is an interesting endpoint
        interesting = (
            status in [200, 201, 202, 204]
            and (content_length > 0 or method in ['GET', 'POST'])
            and ('api' in url.lower() or 'json' in content_type.lower() or 'xml' in content_type.lower())
        )

        # Detect technologies used
        tech_stack = []
        for tech, patterns in self.tech_patterns.items():
            content_str = content_preview.lower()
            headers_str = str(headers).lower()

            if (
                any(re.search(pattern, content_str) for pattern in patterns)
                or any(re.search(pattern, headers_str) for pattern in patterns)
                or any(re.search(pattern, url.lower()) for pattern in patterns)
            ):
                tech_stack.append(tech)

            # Try to extract potential parameters from response
            parameters = []

            if 'json' in content_type.lower() and content:
                try:
                    json_data = json.loads(content)

                    # Extract top-level keys as potential parameters
                    if isinstance(json_data, dict):
                        parameters = list(json_data.keys())
                    else:
                        self.logger.error(f'JSON response is not a dictionary. Type: {type(json_data).__name__}')

                except json.JSONDecodeError as e:
                    self.logger.error(f'Failed to parse JSON from response content: {e}')
                except (TypeError, UnicodeDecodeError) as e:
                    self.logger.error(f'Unexpected error while extracting parameters from JSON: {e}')

        # Create result object
        result = EndpointResult(
            url=url,
            status_code=status,
            method=method,
            content_type=content_type,
            content_length=content_length,
            response_time=response_time,
            auth_required=auth_required,
            api_version=api_version,
            rate_limited=rate_limited,
            rate_limit_headers=rate_limit_headers,
            security_headers=security_headers,
            content_preview=content_preview,
            interesting=interesting,
            tech_stack=tech_stack,
            parameters=parameters[:20],  # Limit to first 20 params
        )

        # Store in appropriate collections
        self.found_endpoints[url] = result

        if interesting:
            self.interesting_endpoints[url] = result

        if auth_required:
            self.auth_required[url] = result

        if rate_limited or rate_limit_headers:
            self.rate_limits[url] = result

        if tech_stack:
            self.tech_stack[url] = tech_stack

        # Look for potential API schema definitions (Swagger/OpenAPI)
        if ('swagger' in url.lower() or 'openapi' in url.lower() or 'api-docs' in url.lower()) and content:
            try:
                schema = json.loads(content)

                if isinstance(schema, dict):
                    if 'swagger' in schema or 'openapi' in schema:
                        self.schema_detected[url] = schema
                    else:
                        self.logger.warning(f"JSON at {url} loaded successfully but no 'swagger' or 'openapi' key found.")
                else:
                    self.logger.error(f'JSON at {url} is not a dictionary. Type: {type(schema).__name__}')
            except json.JSONDecodeError as e:
                self.logger.error(f'Failed to parse JSON from {url}: {e}')
            except (TypeError, UnicodeDecodeError) as e:
                self.logger.error(f'Unexpected error while processing schema at {url}: {e}')

        return result

    async def _post_scan_analysis(self) -> None:
        """Perform additional analysis after completing the initial scan."""
        # Analyze patterns in successful endpoints
        if self.interesting_endpoints:
            self.logger.info(f'Performing post-scan analysis on {len(self.interesting_endpoints)} interesting endpoints')

            # Extract path patterns from successful endpoints to find more
            path_patterns = set()
            for url in self.interesting_endpoints:
                parts = urlparse(url).path.split('/')
                if len(parts) > 2:
                    # Extract patterns like /api/*, /v1/*, etc.
                    pattern = '/'.join(parts[:3]) + '/*'
                    path_patterns.add(pattern)

            # Additional scan based on patterns (implementation omitted for brevity)
            self.logger.info(f'Identified {len(path_patterns)} API path patterns for potential further scanning')

    def get_results_summary(self) -> dict[str, Any]:
        """
        Get a comprehensive summary of scan results.

        Returns:
            Dict[str, Any]: Summary of scan results
        """
        return {
            'target': self.word,
            'total_endpoints_checked': len(self.endpoints),
            'found_endpoints': len(self.found_endpoints),
            'interesting_endpoints': len(self.interesting_endpoints),
            'auth_required_endpoints': len(self.auth_required),
            'rate_limited_endpoints': len(self.rate_limits),
            'api_versions': list(self.api_versions),
            'status_codes': list(self.status_codes),
            'methods': list(self.methods),
            'tech_stack_summary': self._get_tech_stack_summary(),
            'schema_detected': len(self.schema_detected) > 0,
        }

    def _get_tech_stack_summary(self) -> dict[str, int]:
        """Summarize detected technologies."""
        summary: dict[str, int] = {}
        for url, techs in self.tech_stack.items():
            for tech in techs:
                summary[tech] = summary.get(tech, 0) + 1
        return summary

    def get_detailed_results(self) -> list[dict[str, Any]]:
        """
        Get detailed results for all endpoints.

        Returns:
            List[Dict[str, Any]]: List of endpoint result dictionaries
        """
        return [result.to_dict() for result in self.found_endpoints.values()]

    def get_hostnames(self) -> set[str]:
        """Get the set of hostnames found."""
        return self.hosts

    def get_endpoints(self) -> set[str]:
        """Get the set of all endpoints checked."""
        return self.endpoints

    def get_found_endpoints(self) -> dict[str, EndpointResult]:
        """Get dictionary of found and accessible endpoints with detailed results."""
        return self.found_endpoints

    def get_interesting_endpoints(self) -> dict[str, EndpointResult]:
        """Get dictionary of interesting endpoints with detailed results."""
        return self.interesting_endpoints

    def get_auth_required(self) -> dict[str, EndpointResult]:
        """Get dictionary of endpoints requiring authentication with detailed results."""
        return self.auth_required

    def get_api_versions(self) -> set[str]:
        """Get the set of detected API versions."""
        return self.api_versions

    def get_rate_limits(self) -> dict[str, EndpointResult]:
        """Get rate limit information for endpoints with detailed results."""
        return self.rate_limits

    def get_methods(self) -> set[str]:
        """Get the set of HTTP methods used."""
        return self.methods

    def get_status_codes(self) -> set[int]:
        """Get the set of HTTP status codes encountered."""
        return self.status_codes

    def get_response_sizes(self) -> dict[str, int]:
        """Get the response sizes for each endpoint."""
        return self.response_sizes

    def get_tech_stack(self) -> dict[str, list[str]]:
        """Get detected technology stack for endpoints."""
        return self.tech_stack

    def get_schema_detected(self) -> dict[str, dict[str, Any]]:
        """Get detected API schemas (Swagger/OpenAPI)."""
        return self.schema_detected

    def export_results(self, output_file: str | None = None, format: str = 'json') -> str | dict | None:
        """
        Export scan results to a file or return as string/dict.

        Args:
            output_file: Optional file path to save results
            format: Export format ('json', 'dict')

        Returns:
            Union[str, Dict, None]: Results in requested format or None if saved to file
        """
        results = {'summary': self.get_results_summary(), 'endpoints': self.get_detailed_results()}

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            return None

        if format == 'json':
            return json.dumps(results, indent=2)
        else:
            return results
