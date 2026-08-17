"""Check common API paths on an authorized target."""

import asyncio
import json
import logging
import math
import os
import random
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from theHarvester.lib.cancellation import drain_tasks_after_cancellation
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError

logger = logging.getLogger(__name__)
_DIAGNOSTIC_RESPONSE_HEADERS = {
    'allow',
    'content-encoding',
    'content-length',
    'content-type',
    'location',
    'retry-after',
    'www-authenticate',
}


@dataclass
class EndpointResult:
    """Data class for storing endpoint scan results."""

    url: str
    status_code: int = 0
    method: str = ''
    response_headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ''
    content_length: int = 0
    response_time: float = 0.0
    auth_required: bool = False
    api_version: str = ''
    rate_limited: bool = False
    rate_limit_headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, str] = field(default_factory=dict)
    content_preview: str = ''
    body_truncated: bool = False
    interesting: bool = False
    tech_stack: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class SearchApiEndpoints:
    """Check common API paths using only observational HTTP methods."""

    MAX_RETRIES = 2
    DEFAULT_RETRY_DELAY_SECONDS = 0.5
    MAX_RETRY_DELAY_SECONDS = 30.0
    MAX_RETRY_JITTER_SECONDS = 0.5
    MAX_REDIRECTS = 10

    def __init__(
        self,
        word: str,
        wordlist: str | None = None,
        concurrency: int = 10,
        timeout: int = 10,
        proxy: str | None = None,
        user_agent: str | None = None,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        additional_headers: dict[str, str] | None = None,
        exact_paths: bool = False,
        request_limit: int | None = None,
        runtime_seconds: float | None = None,
        response_body_limit: int = 1024 * 1024,
    ) -> None:
        """Configure an API path scan.

        Args:
            word: Hostname to scan.
            wordlist: Path to an optional endpoint wordlist.
            concurrency: Maximum number of requests in flight.
            timeout: Timeout for each request, in seconds.
            proxy: Optional HTTP proxy URL.
            user_agent: HTTP User-Agent value. The default is the shared Chrome identity.
            follow_redirects: Whether requests follow redirects.
            verify_ssl: Whether to verify TLS certificates.
            additional_headers: Extra HTTP headers to send.
            exact_paths: Check only paths listed in the configured wordlist.
            request_limit: Optional maximum requests across schema detection, endpoint methods, and retries.
            runtime_seconds: Optional maximum wall-clock runtime for the endpoint scan.
            response_body_limit: Maximum response body bytes accepted per response.

        """
        if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency <= 0:
            raise ValueError('concurrency must be a positive integer')
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            raise ValueError('timeout must be a positive integer')
        if request_limit is not None and (
            isinstance(request_limit, bool) or not isinstance(request_limit, int) or request_limit <= 0
        ):
            raise ValueError('request_limit must be a positive integer')
        if runtime_seconds is not None and (
            isinstance(runtime_seconds, bool)
            or not isinstance(runtime_seconds, int | float)
            or not math.isfinite(runtime_seconds)
            or runtime_seconds <= 0
        ):
            raise ValueError('runtime_seconds must be positive')
        if isinstance(response_body_limit, bool) or not isinstance(response_body_limit, int) or response_body_limit <= 0:
            raise ValueError('response_body_limit must be a positive integer')
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
        self.user_agent = user_agent or Core.get_browser_user_agent()
        self.additional_headers = additional_headers or {}
        self._session: aiohttp.ClientSession | None = None
        self._ssl_policy = verify_ssl
        self.scan_error_type: str | None = None
        self.request_error_count = 0
        self.request_error_types: set[str] = set()
        self.request_limit = request_limit
        self.request_count = 0
        self.runtime_seconds = runtime_seconds
        self.response_body_limit = response_body_limit
        self.stop_reason: str | None = None

        # Set default wordlist path
        default_wordlist = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'wordlists', 'api_endpoints.txt'
        )
        self.wordlist = wordlist or default_wordlist
        self.exact_paths = exact_paths

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
        """Check common paths with GET, HEAD, and OPTIONS."""
        self.scan_error_type = None
        self.request_error_count = 0
        self.request_error_types.clear()
        self.request_count = 0
        self.stop_reason = None
        connector: aiohttp.BaseConnector | None = None
        session: aiohttp.ClientSession | None = None
        cancellation: asyncio.CancelledError | None = None
        close_error: BaseException | None = None
        deadline = None if self.runtime_seconds is None else asyncio.get_running_loop().time() + self.runtime_seconds
        try:
            self.logger.info(f'Starting API endpoint scan for {self.word}')

            # Load endpoints from wordlist
            endpoints = self._load_wordlist()
            if not endpoints:
                self.logger.warning(f'No endpoints found in wordlist: {self.wordlist}')
                endpoints = []

            if not self.exact_paths:
                endpoints.extend(self.common_api_paths)
            endpoints = list(dict.fromkeys(endpoints))
            if not endpoints:
                return
            worker_count = min(self.concurrency, len(endpoints))
            self._ssl_policy = self.verify_ssl
            connector = aiohttp.TCPConnector(
                limit=worker_count,
                limit_per_host=worker_count,
                ssl=self._ssl_policy,
            )
            session = aiohttp.ClientSession(
                headers=self._get_headers(),
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=connector,
            )
            self._session = session

            # Detect base URL schema (http or https)
            self._claim_request()
            async with asyncio.timeout_at(deadline):
                schema = await self._detect_schema(endpoints[0]) if self.exact_paths else await self._detect_schema()
            self.logger.info(f'Detected schema for {self.word}: {schema}')

            self.logger.info(f'Prepared {len(endpoints)} endpoints to scan with concurrency {self.concurrency}')
            urls = [f'{schema}://{self.word}{endpoint}' for endpoint in endpoints]
            job_indexes = iter(range(len(urls)))

            async def worker() -> None:
                for index in job_indexes:
                    await self._check_endpoint(urls[index])

            workers = [asyncio.create_task(worker(), name=f'api-endpoint-worker-{index}') for index in range(worker_count)]
            worker_error: BaseException | None = None
            try:
                async with asyncio.timeout_at(deadline):
                    await asyncio.gather(*workers)
            except BaseException as error:
                worker_error = error
            interruptions = await drain_tasks_after_cancellation(workers, cancel=worker_error is not None)
            task_errors = tuple(
                task_error for task in workers if not task.cancelled() and (task_error := task.exception()) is not None
            )
            self._order_results(urls)
            if isinstance(worker_error, asyncio.CancelledError):
                raise worker_error
            if interruptions:
                raise interruptions[0]
            if worker_error is not None:
                raise worker_error
            if task_errors:
                raise task_errors[0]

            self.logger.info(f'API endpoint scan completed. Found {len(self.found_endpoints)} endpoints.')

            # Additional processing after scan
            async with asyncio.timeout_at(deadline):
                await self._post_scan_analysis()

        except asyncio.CancelledError as error:
            self.stop_reason = 'cancelled'
            self.scan_error_type = 'CancelledError'
            cancellation = error
        except TimeoutError:
            self.stop_reason = 'runtime-limit'
        except Exception as e:
            self.scan_error_type = type(e).__name__
            self.stop_reason = 'scan-error'
            self.logger.error(f'Error in API endpoint scan: {e!s}', exc_info=True)
        finally:
            self._session = None
            if session is not None or connector is not None:

                async def close_transport() -> None:
                    if session is not None:
                        await session.close()
                    elif connector is not None:
                        await connector.close()

                close_task = asyncio.create_task(close_transport(), name='api-endpoint-session-close')
                interruptions = await drain_tasks_after_cancellation((close_task,), cancel=False)
                if cancellation is None:
                    cleanup_error: BaseException | None = interruptions[0] if interruptions else None
                    if cleanup_error is None and not close_task.cancelled():
                        cleanup_error = close_task.exception()
                    if isinstance(cleanup_error, asyncio.CancelledError):
                        self.stop_reason = 'cancelled'
                        self.scan_error_type = 'CancelledError'
                        cancellation = cleanup_error
                    elif cleanup_error is not None:
                        close_error = cleanup_error
        if cancellation is not None:
            raise cancellation
        if close_error is not None:
            raise close_error

    def _order_results(self, urls: list[str]) -> None:
        self.found_endpoints = {url: self.found_endpoints[url] for url in urls if url in self.found_endpoints}
        self.results = list(self.found_endpoints.values())
        for collection_name in ('interesting_endpoints', 'auth_required', 'rate_limits', 'tech_stack', 'schema_detected'):
            collection = getattr(self, collection_name)
            setattr(self, collection_name, {url: collection[url] for url in urls if url in collection})

    def _claim_request(self) -> bool:
        if self.request_limit is not None and self.request_count >= self.request_limit:
            self.stop_reason = 'request-limit'
            return False
        self.request_count += 1
        return True

    @classmethod
    def _retry_delay(cls, headers: dict[str, str], attempt: int) -> float:
        retry_after = next((value for name, value in headers.items() if name.casefold() == 'retry-after'), '')
        delay: float | None = None
        if retry_after.strip().isdigit():
            delay = float(retry_after)
        elif retry_after:
            try:
                retry_at = parsedate_to_datetime(retry_after)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=UTC)
                delay = max(0.0, (retry_at - datetime.now(UTC)).total_seconds())
            except TypeError, ValueError, OverflowError:
                pass
        if delay is None:
            delay = cls.DEFAULT_RETRY_DELAY_SECONDS * 2**attempt
        jitter = random.uniform(0, cls.MAX_RETRY_JITTER_SECONDS)
        return min(delay + jitter, cls.MAX_RETRY_DELAY_SECONDS)

    async def _detect_schema(self, path: str = '') -> str:
        """Detect if the domain supports HTTPS or fall back to HTTP."""
        https_url = f'https://{self.word}{path}'
        if self._session is None:
            raise RuntimeError('API endpoint session is not initialized')
        try:
            async with self._session.get(
                https_url,
                proxy=self.proxy,
                ssl=self._ssl_policy,
                allow_redirects=False,
            ):
                return 'https'
        except (aiohttp.ClientConnectionError, TimeoutError) as error:
            self.logger.error(f"Failed to connect to HTTPS URL '{https_url}': {error}")
            return 'http'

    def _load_wordlist(self) -> list[str]:
        """Load endpoints from wordlist file with advanced filtering."""
        try:
            with open(self.wordlist) as f:
                lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

            # Ensure all paths start with /
            endpoints = [line if line.startswith('/') else f'/{line}' for line in lines]

            if self.exact_paths:
                return list(dict.fromkeys(endpoints))

            # Add some path variations (with and without trailing slash)
            variations = []
            for endpoint in endpoints:
                variations.append(endpoint)
                if endpoint.endswith('/'):
                    variations.append(endpoint[:-1])  # Without trailing slash
                else:
                    variations.append(f'{endpoint}/')  # With trailing slash

            return list(dict.fromkeys(variations))

        except OSError as e:
            self.logger.error(f'Error loading wordlist {self.wordlist}: {e}')
            return []

    async def _check_endpoint(self, url: str) -> EndpointResult | None:
        """Check if an endpoint exists and analyze its properties.

        Args:
            url: The URL to check.

        Returns:
            Optional[EndpointResult]: Result object or None if not found

        """
        # Other standard HTTP methods can change or delete data on the target.
        methods = ['GET', 'HEAD', 'OPTIONS']
        headers = self._get_headers()

        for method in methods:
            for attempt in range(self.MAX_RETRIES + 1):
                if self.stop_reason in {'request-limit', 'runtime-limit'}:
                    return None
                if not self._claim_request():
                    return None
                try:
                    # Track request time
                    start_time = asyncio.get_running_loop().time()

                    response, body_truncated = await self._fetch_response(url, method, headers)

                    # Calculate response time
                    response_time = asyncio.get_running_loop().time() - start_time

                    if response is None:
                        self.request_error_count += 1
                        self.request_error_types.add('TransportError')
                        break
                    result = self._process_response(url, method, response, response_time, body_truncated=body_truncated)
                    if result is None:
                        break
                    if await self._retry_limited_response(response.status, response.headers, attempt):
                        continue
                    return result

                except ResponseStreamError as error:
                    if error.reason == 'response-limit':
                        response_time = asyncio.get_running_loop().time() - start_time
                        if error.status is not None:
                            result = self._process_response(
                                url,
                                method,
                                FetcherResponse(body='', status=error.status, headers=error.headers),
                                response_time,
                                body_truncated=True,
                            )
                            if await self._retry_limited_response(error.status, error.headers, attempt):
                                continue
                            if error.status in {429, 503}:
                                return result
                            self.request_error_count += 1
                            self.request_error_types.add('ResponseLimitError')
                            self.stop_reason = 'request-errors'
                            return result
                        self.request_error_count += 1
                        self.request_error_types.add('ResponseLimitError')
                        self.stop_reason = 'request-errors'
                        break
                    self.request_error_count += 1
                    self.request_error_types.add('TransportError')
                    break
                except TimeoutError:
                    self.request_error_count += 1
                    self.request_error_types.add('TimeoutError')
                    self.logger.debug(f'Timeout for {method} {url}')
                    break
                except (aiohttp.ClientError, OSError, TypeError, ValueError, AttributeError) as e:
                    self.request_error_count += 1
                    self.request_error_types.add(type(e).__name__)
                    self.logger.debug(f'Error checking {method} {url}: {e!s}')
                    break

        return None

    async def _fetch_response(self, url: str, method: str, headers: dict[str, str]) -> tuple[FetcherResponse | None, bool]:
        current_url = url
        target_hostname = (urlparse(f'//{self.word}').hostname or '').casefold()
        for redirect_count in range(self.MAX_REDIRECTS + 1):
            body_truncated = False
            response_limit_error: ResponseStreamError | None = None
            try:
                response = await AsyncFetcher.fetch(
                    session=self._session,
                    url=current_url,
                    method=method,
                    headers=headers,
                    proxy=self.proxy,
                    verify=self._ssl_policy,
                    follow_redirects=False,
                    request_timeout=self.timeout,
                    include_metadata=True,
                    response_byte_limit=self.response_body_limit,
                )
            except ResponseStreamError as error:
                if error.reason != 'response-limit' or error.status not in {301, 302, 303, 307, 308}:
                    raise
                response = FetcherResponse(body='', status=error.status, headers=error.headers)
                body_truncated = True
                response_limit_error = error
            if response is None or response.status not in {301, 302, 303, 307, 308}:
                return response, body_truncated
            if not self.follow_redirects:
                if response_limit_error is not None:
                    raise response_limit_error
                return response, body_truncated
            location = next((value for name, value in response.headers.items() if name.casefold() == 'location'), '')
            if not location:
                if response_limit_error is not None:
                    raise response_limit_error
                return response, body_truncated
            redirect_url = urljoin(current_url, location)
            parsed_redirect = urlparse(redirect_url)
            if parsed_redirect.scheme not in {'http', 'https'} or (parsed_redirect.hostname or '').casefold() != target_hostname:
                self.request_error_count += 1
                self.request_error_types.add('RedirectScopeError')
                self.stop_reason = 'request-errors'
                return response, body_truncated
            if redirect_count == self.MAX_REDIRECTS:
                self.request_error_count += 1
                self.request_error_types.add('RedirectLimitError')
                self.stop_reason = 'request-errors'
                return response, body_truncated
            if not self._claim_request():
                return response, body_truncated
            current_url = redirect_url
        raise AssertionError('redirect loop exhausted unexpectedly')

    async def _retry_limited_response(self, status: int, headers: dict[str, str], attempt: int) -> bool:
        if status not in {429, 503}:
            return False
        if attempt < self.MAX_RETRIES:
            if self.stop_reason in {'request-limit', 'runtime-limit'}:
                return False
            await asyncio.sleep(self._retry_delay(headers, attempt))
            return True
        if status == 429:
            self.stop_reason = self.stop_reason or 'rate-limited'
        else:
            self.request_error_count += 1
            self.request_error_types.add('HTTP503Error')
            self.stop_reason = 'request-errors'
        return False

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with optional custom additions."""
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        }

        # Add custom headers if provided
        if self.additional_headers:
            headers.update(self.additional_headers)

        return headers

    def _process_response(
        self,
        url: str,
        method: str,
        response: FetcherResponse,
        response_time: float,
        *,
        body_truncated: bool = False,
    ) -> EndpointResult | None:
        """Process and categorize API endpoint response with detailed analysis.

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
        response_headers = {name: value for name, value in headers.items() if name.casefold() in _DIAGNOSTIC_RESPONSE_HEADERS}

        try:
            content_value = getattr(response, 'body', getattr(response, 'content', b''))
            content = content_value.encode() if isinstance(content_value, str) else content_value
            if not isinstance(content, bytes):
                content = b''
        except (TypeError, AttributeError) as e:
            self.logger.error(f'Failed to get content from response for URL {url}: {e}')
            content = b''

        content_length = len(content)
        self.response_sizes[url] = content_length

        # Try to get content type from headers
        content_type = next((value for name, value in headers.items() if name.casefold() == 'content-type'), '')

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

        schema_url = 'swagger' in url.lower() or 'openapi' in url.lower() or 'api-docs' in url.lower()
        json_data: Any = None
        parameters: list[str] = []
        if content and ('json' in content_type.lower() or schema_url):
            try:
                json_data = json.loads(content)
                if 'json' in content_type.lower():
                    if isinstance(json_data, dict):
                        parameters = [key for key in json_data if isinstance(key, str)]
                    else:
                        self.logger.error(f'JSON response is not a dictionary. Type: {type(json_data).__name__}')
            except json.JSONDecodeError as e:
                self.logger.error(f'Failed to parse JSON from response content: {e}')
            except (TypeError, UnicodeDecodeError) as e:
                self.logger.error(f'Unexpected error while extracting parameters from JSON: {e}')

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

        # Create result object
        result = EndpointResult(
            url=url,
            status_code=status,
            method=method,
            response_headers=response_headers,
            content_type=content_type,
            content_length=content_length,
            response_time=response_time,
            auth_required=auth_required,
            api_version=api_version,
            rate_limited=rate_limited,
            rate_limit_headers=rate_limit_headers,
            security_headers=security_headers,
            content_preview=content_preview,
            body_truncated=body_truncated,
            interesting=interesting,
            tech_stack=tech_stack,
            parameters=parameters[:20],  # Limit to first 20 params
        )

        # Store in appropriate collections
        self.found_endpoints[url] = result

        if interesting:
            self.interesting_endpoints[url] = result
        else:
            self.interesting_endpoints.pop(url, None)

        if auth_required:
            self.auth_required[url] = result
        else:
            self.auth_required.pop(url, None)

        if rate_limited or rate_limit_headers:
            self.rate_limits[url] = result
        else:
            self.rate_limits.pop(url, None)

        if tech_stack:
            self.tech_stack[url] = tech_stack
        else:
            self.tech_stack.pop(url, None)

        # Look for potential API schema definitions (Swagger/OpenAPI)
        if schema_url:
            self.schema_detected.pop(url, None)
        if schema_url and content:
            if isinstance(json_data, dict):
                schema_format = 'openapi' if 'openapi' in json_data else 'swagger' if 'swagger' in json_data else ''
                if schema_format:
                    self.schema_detected[url] = json_data
                else:
                    self.logger.warning(f"JSON at {url} loaded successfully but no 'swagger' or 'openapi' key found.")
            elif json_data is not None:
                self.logger.error(f'JSON at {url} is not a dictionary. Type: {type(json_data).__name__}')

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
        """Get a comprehensive summary of scan results.

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
            'api_versions': sorted(self.api_versions),
            'status_codes': sorted(self.status_codes),
            'methods': sorted(self.methods),
            'tech_stack_summary': self._get_tech_stack_summary(),
            'schema_detected': len(self.schema_detected) > 0,
        }

    def _get_tech_stack_summary(self) -> dict[str, int]:
        """Summarize detected technologies."""
        summary: dict[str, int] = {}
        for _url, techs in self.tech_stack.items():
            for tech in techs:
                summary[tech] = summary.get(tech, 0) + 1
        return summary

    def get_detailed_results(self) -> list[dict[str, Any]]:
        """Get detailed results for all endpoints.

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
        """Export scan results to a file or return as string/dict.

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
