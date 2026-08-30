from __future__ import annotations

import asyncio
import contextlib
import json as json_loader
import logging
import os
import random
import re
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal

import aiohttp
import certifi
import yaml
from aiohttp_socks import ProxyConnector

from theHarvester import __version__
from theHarvester.lib.cancellation import drain_tasks_after_cancellation
from theHarvester.lib.output import output_logger
from theHarvester.lib.source_catalog import SOURCE_SPECS, resolve_sources

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sized

    from aiohttp.abc import AbstractCookieJar

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parents[1] / 'data'
CONFIG_DIRS = [
    Path('~/.theHarvester'),
    Path('/etc/theHarvester/'),
    Path('/usr/local/etc/theHarvester/'),
]
MAX_PROVIDER_STREAM_BYTES = 64 * 1024 * 1024
MAX_PROVIDER_JSON_BYTES = 16 * 1024 * 1024
MAX_STREAM_RECORD_BYTES = 10 * 1024 * 1024
_STREAM_LINE_END = re.compile(rb'[\r\n]')

StreamErrorReason = Literal['invalid-response', 'response-limit', 'transport-error']
StreamFraming = Literal['ndjson', 'sse']


class ProxyUnavailableError(Exception):
    pass


class ResponseStreamError(Exception):
    def __init__(
        self,
        reason: StreamErrorReason,
        *,
        status: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.reason = reason
        self.status = status
        self.headers = headers or {}
        super().__init__(reason)


@dataclass(frozen=True)
class FetcherResponse:
    body: Any
    status: int
    headers: dict[str, str]


def _reject_json_constant(value: str) -> None:
    raise ValueError(f'invalid JSON constant: {value}')


async def _bounded_response_chunks(
    content: Any,
    byte_limit: int,
) -> AsyncIterator[bytes]:
    bytes_read = 0
    try:
        async for chunk in content.iter_any():
            remaining = byte_limit - bytes_read
            accepted = chunk[:remaining]
            bytes_read += len(accepted)
            if accepted:
                yield accepted
            if len(accepted) != len(chunk):
                raise ResponseStreamError('response-limit')
    except ResponseStreamError:
        raise
    except (aiohttp.ClientError, TimeoutError, OSError) as error:
        raise ResponseStreamError('transport-error') from error


@dataclass
class TextRecordResponse:
    status: int
    headers: dict[str, str]
    _content: Any
    _framing: StreamFraming
    _started: bool = False

    def __aiter__(self) -> AsyncIterator[str]:
        if self._started:
            raise RuntimeError('response records can only be consumed once')
        self._started = True
        return self._records()

    @staticmethod
    def _decode(line: bytes | bytearray) -> str:
        try:
            return bytes(line).decode('utf-8')
        except UnicodeDecodeError as error:
            raise ResponseStreamError('invalid-response') from error

    async def _byte_lines(self) -> AsyncIterator[tuple[bytes, bool]]:
        pending = bytearray()
        async for chunk in _bounded_response_chunks(self._content, MAX_PROVIDER_STREAM_BYTES):
            pending.extend(chunk)
            start = 0
            while start < len(pending):
                line_end = _STREAM_LINE_END.search(pending, start)
                if line_end is None:
                    break
                separator = line_end.start()
                if pending[separator] == ord('\r') and separator + 1 == len(pending):
                    break
                terminator_bytes = 2 if pending[separator : separator + 2] == b'\r\n' else 1
                line = bytes(pending[start:separator])
                if len(line) > MAX_STREAM_RECORD_BYTES:
                    raise ResponseStreamError('response-limit')
                start = separator + terminator_bytes
                yield line, True
            if start:
                del pending[:start]
            pending_bytes = len(pending) - (1 if pending.endswith(b'\r') else 0)
            if pending_bytes > MAX_STREAM_RECORD_BYTES:
                raise ResponseStreamError('response-limit')
        if pending:
            if pending[-1] == ord('\r'):
                yield bytes(pending[:-1]), True
            else:
                yield bytes(pending), False

    async def _records(self) -> AsyncIterator[str]:
        if self._framing == 'ndjson':
            async for line, _terminated in self._byte_lines():
                yield self._decode(line)
            return

        record = bytearray()
        async for line, terminated in self._byte_lines():
            if not terminated:
                raise ResponseStreamError('invalid-response')
            if not line:
                if record:
                    yield self._decode(record)
                    record.clear()
                continue
            added_bytes = len(line) + (1 if record else 0)
            if len(record) + added_bytes > MAX_STREAM_RECORD_BYTES:
                raise ResponseStreamError('response-limit')
            if record:
                record.append(ord('\n'))
            record.extend(line)
        if record:
            raise ResponseStreamError('invalid-response')


class Core:
    quiet: bool = False
    _API_KEY_FIELDS: ClassVar[dict[str, tuple[str, ...]]] = {
        'bevigil': ('key',),
        'brave': ('key',),
        'bufferoverun': ('key',),
        'builtwith': ('key',),
        'censys': ('token',),
        'criminalip': ('key',),
        'dehashed': ('key',),
        'dnsdb': ('key',),
        'dnsdumpster': ('key',),
        'dymo': ('key',),
        'fofa': ('key', 'email'),
        'fullhunt': ('key',),
        'github': ('key',),
        'hackertarget': ('key',),
        'hibpverified': ('key',),
        'hunter': ('key',),
        'hunterhow': ('key',),
        'intelx': ('key',),
        'leaklookup': ('key',),
        'leakix': ('key',),
        'mojeek': ('key',),
        'netlas': ('key',),
        'onyphe': ('key',),
        'pentestTools': ('key',),
        'projectDiscovery': ('key',),
        'rocketreach': ('key',),
        'routeviews': ('key',),
        'securityscorecard': ('key',),
        'securityTrails': ('key',),
        'sherlockeye': ('key',),
        'shodan': ('key',),
        'tomba': ('key', 'secret'),
        'virustotal': ('key',),
        'whoisxml': ('key',),
        'windvane': ('key',),
        'xquik': ('key',),
        'zoomeye': ('key',),
    }

    @staticmethod
    def _read_config(filename: str) -> str:
        # Return the first we find
        for path in CONFIG_DIRS:
            with contextlib.suppress(FileNotFoundError):
                file = path.expanduser() / filename
                config = file.read_text()
                if not Core.quiet:
                    logger.info(f'Read {filename} from {file}')
                return config

        # Fallback to creating default in the user's home dir
        default = (DATA_DIR / filename).read_text()
        dest = CONFIG_DIRS[0].expanduser() / filename
        dest.parent.mkdir(mode=0o700, exist_ok=True)
        temporary_file = tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=dest.parent,
            prefix=f'.{filename}.',
            delete=False,
        )
        temporary_path = Path(temporary_file.name)
        try:
            with temporary_file:
                os.chmod(temporary_path, 0o600)
                temporary_file.write(default)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            try:
                os.link(temporary_path, dest)
            except FileExistsError:
                config = dest.read_text()
                if not Core.quiet:
                    logger.info(f'Read {filename} from {dest}')
                return config
        finally:
            temporary_path.unlink(missing_ok=True)
        output_logger.info(f'Created default {filename} at {dest}')
        return default

    @staticmethod
    def api_keys() -> dict:
        keys = yaml.safe_load(Core._read_config('api-keys.yaml'))
        return keys['apikeys']

    @staticmethod
    def api_key_fields() -> dict[str, tuple[str, ...]]:
        return dict(Core._API_KEY_FIELDS)

    @staticmethod
    def _api_key_value(provider: str) -> Any:
        provider_keys = Core.api_keys()[provider]
        fields = Core._API_KEY_FIELDS[provider]
        values = tuple(provider_keys[field] for field in fields)
        return values[0] if len(values) == 1 else values

    @staticmethod
    def bevigil_key() -> str:
        return Core._api_key_value('bevigil')

    @staticmethod
    def brave_key() -> str:
        return Core._api_key_value('brave')

    @staticmethod
    def bufferoverun_key() -> str:
        return Core._api_key_value('bufferoverun')

    @staticmethod
    def builtwith_key() -> str:
        return Core._api_key_value('builtwith')

    @staticmethod
    def censys_key() -> tuple[object, object]:
        credentials = Core.api_keys().get('censys', {})
        return credentials.get('token'), credentials.get('organization_id')

    @staticmethod
    def criminalip_key() -> str:
        return Core._api_key_value('criminalip')

    @staticmethod
    def dehashed_key() -> str:
        return Core._api_key_value('dehashed')

    @staticmethod
    def dnsdb_key() -> str:
        return Core._api_key_value('dnsdb')

    @staticmethod
    def dnsdumpster_key() -> str:
        return Core._api_key_value('dnsdumpster')

    @staticmethod
    def dymo_key() -> str:
        return Core._api_key_value('dymo')

    @staticmethod
    def fofa_key() -> tuple[str, str]:
        return Core._api_key_value('fofa')

    @staticmethod
    def fullhunt_key() -> str:
        return Core._api_key_value('fullhunt')

    @staticmethod
    def github_key() -> str:
        return Core._api_key_value('github')

    @staticmethod
    def hackertarget_key() -> str:
        return Core._api_key_value('hackertarget')

    @staticmethod
    def hibpverified_key() -> str | None:
        return Core.api_keys().get('hibpverified', {}).get('key')

    @staticmethod
    def hunter_key() -> str:
        return Core._api_key_value('hunter')

    @staticmethod
    def hunterhow_key() -> str:
        return Core._api_key_value('hunterhow')

    @staticmethod
    def intelx_key() -> str:
        return Core._api_key_value('intelx')

    @staticmethod
    def leaklookup_key() -> str:
        return Core._api_key_value('leaklookup')

    @staticmethod
    def mojeek_key() -> str:
        return Core._api_key_value('mojeek')

    @staticmethod
    def leakix_key() -> str:
        return Core._api_key_value('leakix')

    @staticmethod
    def netlas_key() -> str:
        return Core._api_key_value('netlas')

    @staticmethod
    def onyphe_key() -> str:
        return Core._api_key_value('onyphe')

    @staticmethod
    def pentest_tools_key() -> str:
        return Core._api_key_value('pentestTools')

    @staticmethod
    def projectdiscovery_key() -> str:
        return Core._api_key_value('projectDiscovery')

    @staticmethod
    def rocketreach_key() -> str:
        return Core._api_key_value('rocketreach')

    @staticmethod
    def routeviews_key() -> str | None:
        value = Core.api_keys().get('routeviews', {}).get('key')
        return value.strip() if isinstance(value, str) and value.strip() else None

    @staticmethod
    def securityscorecard_key() -> str:
        return Core._api_key_value('securityscorecard')

    @staticmethod
    def security_trails_key() -> str:
        return Core._api_key_value('securityTrails')

    @staticmethod
    def sherlockeye_key() -> str:
        return Core._api_key_value('sherlockeye')

    @staticmethod
    def shodan_key() -> str:
        return Core._api_key_value('shodan')

    @staticmethod
    def tomba_key() -> tuple[str, str]:
        return Core._api_key_value('tomba')

    @staticmethod
    def virustotal_key() -> str:
        return Core._api_key_value('virustotal')

    @staticmethod
    def whoisxml_key() -> str:
        return Core._api_key_value('whoisxml')

    @staticmethod
    def windvane_key() -> str:
        return Core._api_key_value('windvane')

    @staticmethod
    def xquik_key() -> str:
        return Core._api_key_value('xquik')

    @staticmethod
    def zoomeye_key() -> str:
        return Core._api_key_value('zoomeye')

    @staticmethod
    def _proxy_urls(config: dict[str, list[str] | None], proxy_type: str) -> list[str]:
        proxies = config.get(proxy_type)
        return [f'{proxy_type}://{proxy}' for proxy in proxies] if proxies else []

    @staticmethod
    def proxy_list() -> dict:
        keys = yaml.safe_load(Core._read_config('proxies.yaml'))
        return {
            'http': Core._proxy_urls(keys, 'http'),
            'socks5': Core._proxy_urls(keys, 'socks5'),
        }

    @staticmethod
    def banner() -> None:
        output_logger.info('*******************************************************************')
        output_logger.info('*  _   _                                            _             *')
        output_logger.info(r'* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *')
        output_logger.info(r"* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *")
        output_logger.info(r'* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *')
        output_logger.info(r'*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *')
        output_logger.info('*                                                                 *')
        output_logger.info('* theHarvester {version}{filler}*'.format(version=__version__, filler=' ' * (51 - len(__version__))))
        output_logger.info('* Coded by Christian Martorella                                   *')
        output_logger.info('* Edge-Security Research                                          *')
        output_logger.info('* cmartorella@edge-security.com                                   *')
        output_logger.info('*                                                                 *')
        output_logger.info('*******************************************************************')

    @staticmethod
    def get_supportedengines() -> list[str]:
        """Return the canonical discovery-source inventory."""
        return sorted(SOURCE_SPECS)

    @classmethod
    def expand_source_selection(cls, selection: str) -> list[str]:
        """Expand result capability selectors into source names."""
        return resolve_sources(selection)

    @staticmethod
    def get_user_agent() -> str:
        """Return the stable identity used for provider and API requests."""
        return f'theHarvester/{__version__} (+https://github.com/laramies/theHarvester)'

    @staticmethod
    def get_browser_user_agent() -> str:
        """Return the Chrome identity used only for browser-oriented sources."""
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36'


class AsyncFetcher:
    _proxy_list: ClassVar[dict | None] = None

    @property
    def proxy_list(self) -> dict:
        """Load and cache proxies on first use instead of during module import."""

        proxy_list = self.__class__._proxy_list
        if proxy_list is None:
            proxy_list = Core.proxy_list()
            self.__class__._proxy_list = proxy_list
        return proxy_list

    @staticmethod
    def _default_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
        request_headers = dict(headers or {})
        if not any(name.lower() == 'user-agent' for name in request_headers):
            request_headers['User-Agent'] = Core.get_user_agent()
        return request_headers

    @staticmethod
    def _ssl_context(verify: bool | None = True) -> ssl.SSLContext | bool:
        if verify is False:
            return False
        return ssl.create_default_context(cafile=certifi.where())

    @staticmethod
    def _request_timeout(total: int | None) -> aiohttp.ClientTimeout | None:
        return aiohttp.ClientTimeout(total=total) if total else None

    @staticmethod
    def _normalize_data(data: str | dict[str, Any]) -> str | dict[str, Any]:
        return json_loader.loads(data) if isinstance(data, str) else data

    @classmethod
    def _resolve_proxy(cls, proxy: str | bool | None) -> tuple[str | None, str | None]:
        if isinstance(proxy, str) and proxy != '':
            return proxy, 'socks5' if proxy.startswith('socks5://') else 'http'
        if isinstance(proxy, bool) and proxy:
            try:
                resolved = cls._get_random_proxy(cls().proxy_list)
            except IndexError, TypeError, ValueError:
                resolved = (None, None)
            if resolved[0] is None:
                raise ProxyUnavailableError('proxy-unavailable')
            return resolved
        return None, None

    @classmethod
    async def _build_session(
        cls,
        headers: dict[str, str],
        client_timeout: aiohttp.ClientTimeout | None,
        proxy_url: str | None = None,
        proxy_type: str | None = None,
        ssl_context: ssl.SSLContext | bool | None = None,
        cookie_jar: AbstractCookieJar | None = None,
    ) -> aiohttp.ClientSession:
        connector = None
        if proxy_url is not None or proxy_type is not None or ssl_context is not None:
            connector = await cls._create_connector(proxy_url, proxy_type, ssl_context)
        session_kwargs: dict[str, Any] = {
            'headers': headers,
            'timeout': client_timeout,
            'connector': connector,
        }
        if proxy_url is not None and proxy_type == 'http':
            session_kwargs['proxy'] = proxy_url
        if cookie_jar is not None:
            session_kwargs['cookie_jar'] = cookie_jar
        return aiohttp.ClientSession(**session_kwargs)

    @classmethod
    @contextlib.asynccontextmanager
    async def open_session(
        cls,
        *,
        headers: dict[str, str] | None = None,
        proxy: str | bool | None = '',
        request_timeout: int | None = None,
        cookie_jar: AbstractCookieJar | None = None,
    ) -> AsyncIterator[aiohttp.ClientSession]:
        """Own one connection pool, proxy identity, and cookie jar for a provider conversation."""
        proxy_url, proxy_type = cls._resolve_proxy(proxy)
        session = await cls._build_session(
            cls._default_headers(headers),
            cls._request_timeout(request_timeout),
            proxy_url,
            proxy_type,
            cls._ssl_context(),
            cookie_jar,
        )
        body_error: BaseException | None = None
        try:
            yield session
        except BaseException as error:
            body_error = error
        close_task = asyncio.create_task(session.close(), name='provider-http-session-close')
        interruptions = await drain_tasks_after_cancellation((close_task,), cancel=False)
        close_error = None if close_task.cancelled() else close_task.exception()
        if body_error is not None:
            raise body_error
        if interruptions:
            raise interruptions[0]
        if close_error is not None:
            raise close_error

    @staticmethod
    async def _read_response(
        response: aiohttp.ClientResponse,
        *,
        json: bool,
        include_metadata: bool = False,
        response_byte_limit: int | None = None,
    ) -> Any:
        if response_byte_limit is not None:
            response_headers = {name.lower(): value for name, value in response.headers.items()}
            try:
                try:
                    if int(response_headers.get('content-length', '0')) > response_byte_limit:
                        raise ResponseStreamError('response-limit')
                except ValueError:
                    pass
                body_bytes = bytearray()
                async for chunk in _bounded_response_chunks(response.content, response_byte_limit):
                    body_bytes.extend(chunk)
            except ResponseStreamError as error:
                if error.status is None:
                    error.status = response.status
                    error.headers = response_headers
                raise
            text_body = bytes(body_bytes).decode(getattr(response, 'charset', None) or 'utf-8', errors='replace')
            if json and text_body.strip():
                try:
                    body = json_loader.loads(text_body)
                except ValueError:
                    if not include_metadata:
                        raise
                    body = text_body
            else:
                body = text_body
        elif json is False:
            body = await response.text()
        elif include_metadata:
            text_body = await response.text()
            if not text_body.strip():
                body = text_body
            else:
                try:
                    body = await response.json()
                except aiohttp.ContentTypeError, ValueError:
                    body = text_body
        else:
            body = await response.json()
        if not include_metadata:
            return body
        return FetcherResponse(
            body=body,
            status=response.status,
            headers={name.lower(): value for name, value in response.headers.items()},
        )

    @classmethod
    async def _request(
        cls,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        *,
        json: bool = False,
        json_body: dict[str, Any] | None = None,
        request_timeout: int | None = None,
        include_metadata: bool = False,
        response_byte_limit: int | None = None,
        **request_kwargs: Any,
    ) -> Any:
        if json_body is not None:
            request_kwargs.pop('data', None)
            request_kwargs['json'] = json_body
        if request_timeout:
            async with asyncio.timeout(request_timeout):
                async with session.request(method.upper(), url, **request_kwargs) as response:
                    return await cls._read_response(
                        response,
                        json=json,
                        include_metadata=include_metadata,
                        response_byte_limit=response_byte_limit,
                    )

        async with session.request(method.upper(), url, **request_kwargs) as response:
            return await cls._read_response(
                response,
                json=json,
                include_metadata=include_metadata,
                response_byte_limit=response_byte_limit,
            )

    @staticmethod
    def _get_random_proxy(proxy_dict: dict) -> tuple[str | None, str | None]:
        """Return a random proxy URL and its ``http`` or ``socks5`` type."""
        all_proxies = []
        for proxy_type, proxies in proxy_dict.items():
            if proxies:
                for proxy in proxies:
                    all_proxies.append((proxy, proxy_type))

        if not all_proxies:
            return None, None

        return random.choice(all_proxies)

    @staticmethod
    async def _create_connector(
        proxy_url: str | None, proxy_type: str | None, ssl_context: ssl.SSLContext | bool | None = None
    ) -> aiohttp.BaseConnector:
        """Create an aiohttp connector for the selected proxy type."""
        if proxy_url and proxy_type == 'socks5':
            # Create SOCKS5 proxy connector using aiohttp-socks
            # ProxyConnector.from_url can handle socks5://host:port URLs
            connector = ProxyConnector.from_url(proxy_url, ssl=ssl_context)
            return connector
        else:
            # Use default TCP connector for HTTP proxies or no proxy
            return aiohttp.TCPConnector(ssl=ssl_context or ssl.create_default_context(cafile=certifi.where()))

    @classmethod
    async def post_fetch(
        cls,
        url: str,
        headers: dict[str, str] | None = None,
        data: str | dict[str, Any] = '',
        params: Sized = '',
        json: bool = False,
        proxy: str | bool | None = False,
        include_metadata: bool = False,
        json_body: dict[str, Any] | None = None,
        *,
        session: aiohttp.ClientSession | None = None,
    ) -> Any:
        headers = cls._default_headers(headers)
        # By default, timeout is 5 minutes, changed to 12-minutes
        # results are well worth the wait
        try:
            if session is None:
                async with cls.open_session(headers=headers, proxy=proxy, request_timeout=720) as owned_session:
                    return await cls.post_fetch(
                        url,
                        session=owned_session,
                        data=data,
                        params=params,
                        json=json,
                        include_metadata=include_metadata,
                        json_body=json_body,
                    )
            request_kwargs: dict[str, Any] = {
                'data': cls._normalize_data(data) if json_body is None else None,
            }
            if params != '':
                request_kwargs['params'] = params
            return await cls._request(
                session,
                'POST',
                url,
                json=json,
                json_body=json_body,
                include_metadata=include_metadata,
                **request_kwargs,
            )
        except aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError, UnicodeDecodeError, ValueError:
            return None if include_metadata else ''

    @classmethod
    async def fetch(
        cls,
        session: aiohttp.ClientSession | None = None,
        url: str = '',
        params: Sized = '',
        json: bool = False,
        proxy: str | bool | None = '',
        headers: dict[str, str] | None = None,
        method: str = 'GET',
        verify: bool | None = None,
        follow_redirects: bool | None = None,
        request_timeout: int | None = None,
        include_metadata: bool = False,
        response_byte_limit: int | None = None,
    ) -> Any:
        """Send an HTTP request and return its text or JSON body.

        When no session is supplied, this method creates and closes one. It
        supports custom headers, methods, proxies, TLS verification, redirects,
        and timeouts. A response that exceeds an explicit byte limit raises
        ``ResponseStreamError`` instead of buffering the remaining body.
        """
        try:
            owns_session = session is None
            ssl_arg = cls._ssl_context(verify) if owns_session or not isinstance(verify, bool) else verify
            proxy_url, proxy_type = cls._resolve_proxy(proxy)
            client_timeout = cls._request_timeout(request_timeout)
            req_headers = cls._default_headers(headers)

            # Decide whether we need to manage the session
            if owns_session:
                # Create connector based on proxy type
                session = (
                    await cls._build_session(req_headers, client_timeout, proxy_url, proxy_type, ssl_arg)
                    if proxy_url
                    else await cls._build_session(req_headers, client_timeout)
                )
            assert session is not None

            try:
                request_kwargs: dict[str, Any] = {
                    'ssl': ssl_arg,
                }
                # For HTTP proxies, pass the proxy parameter; for SOCKS5, the connector handles it
                if proxy_url and proxy_type == 'http':
                    request_kwargs['proxy'] = proxy_url
                if follow_redirects is not None:
                    request_kwargs['allow_redirects'] = follow_redirects
                if params != '':
                    request_kwargs['params'] = params
                return await cls._request(
                    session,
                    method,
                    url,
                    json=json,
                    request_timeout=request_timeout,
                    include_metadata=include_metadata,
                    response_byte_limit=response_byte_limit,
                    **request_kwargs,
                )
            finally:
                if owns_session:
                    await session.close()
        except aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError, UnicodeDecodeError, ValueError:
            return None if include_metadata else ''

    @classmethod
    @contextlib.asynccontextmanager
    async def _open_get_response(
        cls,
        url: str,
        *,
        session: aiohttp.ClientSession | None = None,
        params: Sized = '',
        proxy: str | bool | None = '',
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
        request_timeout: int | None = 60,
    ) -> AsyncIterator[aiohttp.ClientResponse]:
        owns_session = session is None
        proxy_url, proxy_type = cls._resolve_proxy(proxy)
        ssl_arg: ssl.SSLContext | bool | None = None
        if owns_session:
            try:
                ssl_arg = cls._ssl_context()
                session = await cls._build_session(
                    cls._default_headers(headers),
                    aiohttp.ClientTimeout(total=request_timeout),
                    proxy_url,
                    proxy_type,
                    ssl_arg,
                )
            except (aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError, ValueError) as error:
                raise ResponseStreamError('transport-error') from error
        assert session is not None
        try:
            request_kwargs: dict[str, Any] = {'allow_redirects': follow_redirects}
            if owns_session:
                request_kwargs['ssl'] = ssl_arg
            elif headers is not None:
                request_kwargs['headers'] = cls._default_headers(headers)
            if proxy_url and proxy_type == 'http':
                request_kwargs['proxy'] = proxy_url
            if params != '':
                request_kwargs['params'] = params
            async with contextlib.AsyncExitStack() as stack:
                try:
                    response = await stack.enter_async_context(session.request('GET', url, **request_kwargs))
                except (aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError, ValueError) as error:
                    raise ResponseStreamError('transport-error') from error
                yield response
        finally:
            if owns_session:
                await session.close()

    @classmethod
    async def fetch_json(
        cls,
        url: str,
        *,
        session: aiohttp.ClientSession | None = None,
        params: Sized = '',
        proxy: str | bool | None = '',
        headers: dict[str, str] | None = None,
        request_timeout: int | None = 60,
    ) -> FetcherResponse:
        """Fetch one bounded JSON response without following redirects."""
        async with cls._open_get_response(
            url,
            session=session,
            params=params,
            proxy=proxy,
            headers=headers,
            follow_redirects=False,
            request_timeout=request_timeout,
        ) as response:
            response_headers = {name.lower(): value for name, value in response.headers.items()}
            if not 200 <= response.status < 300 or response.status == 204:
                return FetcherResponse(body=None, status=response.status, headers=response_headers)
            try:
                if int(response_headers.get('content-length', '0')) > MAX_PROVIDER_JSON_BYTES:
                    raise ResponseStreamError('response-limit')
            except ValueError:
                pass
            body = bytearray()
            async for chunk in _bounded_response_chunks(response.content, MAX_PROVIDER_JSON_BYTES):
                body.extend(chunk)
            try:
                text = body.decode('utf-8')
                if not text.strip():
                    raise ValueError('empty JSON response')
                parsed = json_loader.loads(text, parse_constant=_reject_json_constant)
            except (UnicodeDecodeError, ValueError, RecursionError) as error:
                raise ResponseStreamError('invalid-response') from error
            return FetcherResponse(body=parsed, status=response.status, headers=response_headers)

    @classmethod
    async def fetch_text(
        cls,
        url: str,
        *,
        session: aiohttp.ClientSession | None = None,
        proxy: str | bool | None = '',
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
        request_timeout: int | None = None,
        response_byte_limit: int = MAX_PROVIDER_JSON_BYTES,
    ) -> FetcherResponse:
        """Fetch one bounded text response while preserving status and headers."""
        if isinstance(response_byte_limit, bool) or not isinstance(response_byte_limit, int) or response_byte_limit <= 0:
            raise ValueError('response byte limit must be greater than zero')
        async with cls._open_get_response(
            url,
            session=session,
            proxy=proxy,
            headers=headers,
            follow_redirects=follow_redirects,
            request_timeout=request_timeout,
        ) as response:
            response_headers = {name.lower(): value for name, value in response.headers.items()}
            try:
                try:
                    if int(response_headers.get('content-length', '0')) > response_byte_limit:
                        raise ResponseStreamError('response-limit')
                except ValueError:
                    pass
                body = bytearray()
                async for chunk in _bounded_response_chunks(response.content, response_byte_limit):
                    body.extend(chunk)
            except ResponseStreamError as error:
                if error.status is None:
                    error.status = response.status
                    error.headers = response_headers
                raise
            return FetcherResponse(
                body=bytes(body).decode(getattr(response, 'charset', None) or 'utf-8', errors='replace'),
                status=response.status,
                headers=response_headers,
            )

    @classmethod
    @contextlib.asynccontextmanager
    async def stream_records(
        cls,
        url: str,
        *,
        framing: StreamFraming,
        params: Sized = '',
        proxy: str | bool | None = '',
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
        request_timeout: int = 60,
    ) -> AsyncIterator[TextRecordResponse]:
        """Stream bounded UTF-8 NDJSON lines or complete SSE events.

        The returned response is single-use. Redirects are disabled unless the
        caller explicitly opts in, and transport/body failures use
        ``ResponseStreamError`` while cancellation and consumer errors pass through.
        """
        if framing not in {'ndjson', 'sse'}:
            raise ValueError(f'unsupported stream framing: {framing}')
        async with cls._open_get_response(
            url,
            params=params,
            proxy=proxy,
            headers=headers,
            follow_redirects=follow_redirects,
            request_timeout=request_timeout,
        ) as response:
            yield TextRecordResponse(
                status=response.status,
                headers={name.lower(): value for name, value in response.headers.items()},
                _content=response.content,
                _framing=framing,
            )

    @classmethod
    async def fetch_all(
        cls,
        urls: list[str],
        headers: dict[str, str] | None = None,
        params: Sized = '',
        json: bool = False,
        proxy: str | bool | None = False,
        include_metadata: bool = False,
        *,
        session: aiohttp.ClientSession | None = None,
    ) -> list[Any]:
        if session is not None:
            if proxy:
                raise ValueError('proxy selection is not supported with a caller-owned session')
            return list(
                await asyncio.gather(
                    *[
                        AsyncFetcher.fetch(
                            session=session,
                            url=url,
                            params=params,
                            json=json,
                            include_metadata=include_metadata,
                        )
                        for url in urls
                    ]
                )
            )
        # By default, timeout is 5 minutes; 60 seconds should suffice
        async with cls.open_session(headers=headers, proxy=proxy, request_timeout=60) as owned_session:
            return list(
                await asyncio.gather(
                    *[
                        cls.fetch(
                            session=owned_session,
                            url=url,
                            params=params,
                            json=json,
                            include_metadata=include_metadata,
                        )
                        for url in urls
                    ]
                )
            )


def show_default_error_message(engine_name: str, word: str, error) -> None:
    output_logger.info(f"Failed to process {engine_name} search for word: '{word}'")
    output_logger.info(f'Error Message: {error}')
