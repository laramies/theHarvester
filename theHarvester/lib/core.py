from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import urlsplit

import aiohttp
import certifi

# need to import as different name as to not shadow already existing json var in post_fetch
import ujson as json_loader
import yaml
from aiohttp_socks import ProxyConnector

from theHarvester import __version__
from theHarvester.lib.output import output_logger
from theHarvester.lib.public_egress import PublicResolver
from theHarvester.lib.source_catalog import resolve_sources

if TYPE_CHECKING:
    from collections.abc import Sized

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parents[1] / 'data'
CONFIG_DIRS = [
    Path('~/.theHarvester'),
    Path('/etc/theHarvester/'),
    Path('/usr/local/etc/theHarvester/'),
]


@dataclass(frozen=True)
class FetcherResponse:
    body: Any
    status: int
    headers: dict[str, str]


class Core:
    quiet: bool = False
    _API_KEY_FIELDS: ClassVar[dict[str, tuple[str, ...]]] = {
        'bevigil': ('key',),
        'brave': ('key',),
        'bufferoverun': ('key',),
        'builtwith': ('key',),
        'censys': ('id', 'secret'),
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
        'securityscorecard': ('key',),
        'securityTrails': ('key',),
        'sherlockeye': ('key',),
        'shodan': ('key',),
        'tomba': ('key', 'secret'),
        'virustotal': ('key',),
        'whoisxml': ('key',),
        'windvane': ('key',),
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
        dest.parent.mkdir(exist_ok=True)
        dest.write_text(default)
        output_logger.info(f'Created default {filename} at {dest}')
        return default

    @staticmethod
    def api_keys() -> dict:
        keys = yaml.safe_load(Core._read_config('api-keys.yaml'))
        return keys['apikeys']

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
    def censys_key() -> tuple:
        return Core._api_key_value('censys')

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
        """Returns a list of supported search engines."""
        return [
            'arquivo',
            'baidu',
            'bevigil',
            'bufferoverun',
            'builtwith',
            'brave',
            'censys',
            'certspotter',
            'chaos',
            'commoncrawl',
            'criminalip',
            'crtsh',
            'dehashed',
            'dnsdb',
            'dnsdumpster',
            'duckduckgo',
            'dymo',
            'fofa',
            'fullhunt',
            'github-code',
            'gitlab',
            'hackertarget',
            'haveibeenpwned',
            'hibpverified',
            'hudsonrock',
            'hunter',
            'hunterhow',
            'intelx',
            'leakix',
            'leaklookup',
            'linkedin',
            'linkedin_links',
            'mojeek',
            'netcraft',
            'netlas',
            'omnisint',
            'onyphe',
            'otx',
            'pentesttools',
            'projectdiscovery',
            'rapiddns',
            'robtex',
            'rocketreach',
            'securityscorecard',
            'securityTrails',
            'sherlockeye',
            'shodan',
            'shodanInternetDB',
            'shodanct',
            'subdomaincenter',
            'subdomainfinderc99',
            'sublist3r',
            'thc',
            'tomba',
            'urlscan',
            'virustotal',
            'waybackarchive',
            'whoisxml',
            'windvane',
            'yahoo',
            'zoomeye',
            'zoomeyeapi',
        ]

    @classmethod
    def expand_source_selection(cls, selection: str) -> list[str]:
        """Expand result capability selectors into source names."""
        return resolve_sources(selection)

    @staticmethod
    def get_user_agent() -> str:
        # User-Agents from https://techblog.willshouse.com/2012/01/03/most-common-user-agents/
        # Lasted updated 21-12-25
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 OPR/124.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 OPR/123.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36; Manus-User/1.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0',
            'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0',
        ]
        return random.choice(user_agents)


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
        return headers or {'User-Agent': Core.get_user_agent()}

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
                return cls._get_random_proxy(cls().proxy_list)
            except (IndexError, TypeError, ValueError):
                return None, None
        return None, None

    @classmethod
    async def _build_session(
        cls,
        headers: dict[str, str],
        client_timeout: aiohttp.ClientTimeout | None,
        proxy_url: str | None = None,
        proxy_type: str | None = None,
        ssl_context: ssl.SSLContext | bool | None = None,
    ) -> aiohttp.ClientSession:
        connector = None
        if proxy_url is not None or proxy_type is not None:
            connector = await cls._create_connector(proxy_url, proxy_type, ssl_context)
        return aiohttp.ClientSession(headers=headers, timeout=client_timeout, connector=connector)

    @staticmethod
    async def _read_response(
        response: aiohttp.ClientResponse,
        *,
        json: bool,
        delay: int,
        include_metadata: bool = False,
    ) -> Any:
        await asyncio.sleep(delay)
        if json is False:
            body = await response.text()
        elif include_metadata:
            text_body = await response.text()
            if not text_body.strip():
                body = text_body
            else:
                try:
                    body = await response.json()
                except (aiohttp.ContentTypeError, ValueError):
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
        delay: int = 5,
        request_timeout: int | None = None,
        include_metadata: bool = False,
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
                        delay=delay,
                        include_metadata=include_metadata,
                    )

        async with session.request(method.upper(), url, **request_kwargs) as response:
            return await cls._read_response(
                response,
                json=json,
                delay=delay,
                include_metadata=include_metadata,
            )

    @staticmethod
    def _get_random_proxy(proxy_dict: dict) -> tuple[str | None, str | None]:
        """Get a random proxy from the proxy dictionary.
        Returns (proxy_url, proxy_type) where proxy_type is 'http' or 'socks5'
        """
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
        """Create an appropriate connector for the given proxy type.
        Returns a connector that can be used with aiohttp.ClientSession.
        """
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
        url,
        headers=None,
        data: str | dict[str, Any] = '',
        params: Sized = '',
        json: bool = False,
        proxy: bool = False,
        include_metadata: bool = False,
        json_body: dict[str, Any] | None = None,
    ):
        headers = cls._default_headers(headers)
        timeout = cls._request_timeout(720)
        # By default, timeout is 5 minutes, changed to 12-minutes
        # results are well worth the wait
        try:
            if proxy:
                proxy_url, proxy_type = cls._resolve_proxy(proxy)
                sslcontext = cls._ssl_context()
                request_kwargs: dict[str, Any] = {
                    'data': cls._normalize_data(data) if json_body is None else None,
                    'proxy': proxy_url if proxy_type == 'http' else None,
                }
                if params != '':
                    request_kwargs['params'] = params
                async with await cls._build_session(headers, timeout, proxy_url, proxy_type, sslcontext) as session:
                    return await cls._request(
                        session,
                        'POST',
                        url,
                        json=json,
                        json_body=json_body,
                        delay=3,
                        include_metadata=include_metadata,
                        **request_kwargs,
                    )
            elif params == '':
                async with await cls._build_session(headers, timeout) as session:
                    return await cls._request(
                        session,
                        'POST',
                        url,
                        data=cls._normalize_data(data) if json_body is None else None,
                        json=json,
                        json_body=json_body,
                        delay=3,
                        include_metadata=include_metadata,
                    )
            else:
                async with await cls._build_session(headers, timeout) as session:
                    return await cls._request(
                        session,
                        'POST',
                        url,
                        data=cls._normalize_data(data) if json_body is None else None,
                        ssl=cls._ssl_context(),
                        params=params,
                        json=json,
                        json_body=json_body,
                        delay=3,
                        include_metadata=include_metadata,
                    )
        except (aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError, UnicodeDecodeError, ValueError):
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
    ) -> Any:
        """Generic HTTP request helper.
        - If a session is not provided, one will be created and closed automatically.
        - Supports optional headers, method selection, proxy, ssl verification, redirects and timeout.
        - Returns response text or json depending on `json` flag.
        """
        try:
            ssl_arg = cls._ssl_context(verify)
            proxy_url, proxy_type = cls._resolve_proxy(proxy)
            client_timeout = cls._request_timeout(request_timeout)
            req_headers = cls._default_headers(headers)

            # Decide whether we need to manage the session
            owns_session = session is None
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
                    delay=5,
                    request_timeout=request_timeout,
                    include_metadata=include_metadata,
                    **request_kwargs,
                )
            finally:
                if owns_session:
                    await session.close()
        except (aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError, UnicodeDecodeError, ValueError):
            return None if include_metadata else ''

    @staticmethod
    async def takeover_fetch(
        session,
        url: str,
        proxy: str | None = None,
        resolver: PublicResolver | None = None,
    ) -> tuple[Any, Any] | str:
        # This fetch method solely focuses on get requests
        try:
            parsed = urlsplit(url)
            if parsed.hostname is None:
                raise ValueError('Takeover target does not identify a host')
            if proxy:
                logger.info('Refusing takeover proxy that cannot pin the validated target address')
                return url, ''
            resolver = resolver or PublicResolver()
            await resolver.resolve(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
            # Wrap in try except due to 0x89 png/jpg files
            # This fetch method solely focuses on get requests
            # TODO determine if method for post requests is necessary
            # url = f'http://{url}' if str(url).startswith(('http:', 'https:')) is False else url
            # Clean up urls with proper schemas
            if proxy:
                if 'https://' in url:
                    sslcontext = ssl.create_default_context(cafile=certifi.where())
                    async with session.get(url, proxy=proxy, ssl=sslcontext, allow_redirects=False) as response:
                        await asyncio.sleep(5)
                        return url, await response.text()
                else:
                    async with session.get(url, proxy=proxy, ssl=False, allow_redirects=False) as response:
                        await asyncio.sleep(5)
                        return url, await response.text()
            elif 'https://' in url:
                sslcontext = ssl.create_default_context(cafile=certifi.where())
                async with session.get(url, ssl=sslcontext, allow_redirects=False) as response:
                    await asyncio.sleep(5)
                    return url, await response.text()
            else:
                async with session.get(url, ssl=False, allow_redirects=False) as response:
                    await asyncio.sleep(5)
                    return url, await response.text()
        except (aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError, UnicodeDecodeError, ValueError) as e:
            logger.info(f'Takeover check error: {e}')
            return url, ''

    @classmethod
    async def fetch_all(
        cls,
        urls,
        headers=None,
        params: Sized = '',
        json: bool = False,
        takeover: bool = False,
        proxy: bool = False,
        include_metadata: bool = False,
    ) -> list:
        # By default, timeout is 5 minutes; 60 seconds should suffice
        headers = cls._default_headers(headers)
        timeout = cls._request_timeout(60)
        if takeover:
            resolver = PublicResolver()
            connector = aiohttp.TCPConnector(resolver=resolver)
            async with aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
                connector=connector,
            ) as session:
                if proxy:
                    # Get random proxy for each URL
                    proxy_urls = [cls._get_random_proxy(cls().proxy_list)[0] for _ in urls]
                    if any(proxy_url is None for proxy_url in proxy_urls):
                        logger.info('Refusing takeover checks because no proxy is configured')
                        return [(url, '') for url in urls]
                    return list(
                        await asyncio.gather(
                            *[
                                AsyncFetcher.takeover_fetch(session, url, proxy=proxy_url, resolver=resolver)
                                for url, proxy_url in zip(urls, proxy_urls, strict=False)
                            ]
                        )
                    )
                else:
                    return list(
                        await asyncio.gather(*[AsyncFetcher.takeover_fetch(session, url, resolver=resolver) for url in urls])
                    )

        if len(params) == 0:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                if proxy:
                    # Get random proxy for each URL (returns tuple of proxy_url and proxy_type)
                    proxy_data = [cls._get_random_proxy(cls().proxy_list) for _ in urls]
                    return list(
                        await asyncio.gather(
                            *[
                                AsyncFetcher.fetch(
                                    session,
                                    url,
                                    json=json,
                                    proxy=proxy_url,
                                    include_metadata=include_metadata,
                                )
                                for url, (proxy_url, proxy_type) in zip(urls, proxy_data, strict=False)
                            ]
                        )
                    )
                else:
                    return list(
                        await asyncio.gather(
                            *[AsyncFetcher.fetch(session, url, json=json, include_metadata=include_metadata) for url in urls]
                        )
                    )
        else:
            # Indicates the request has certain params
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                if proxy:
                    proxy_data = [cls._get_random_proxy(cls().proxy_list) for _ in urls]
                    return list(
                        await asyncio.gather(
                            *[
                                AsyncFetcher.fetch(
                                    session,
                                    url,
                                    params,
                                    json,
                                    proxy=proxy_url,
                                    include_metadata=include_metadata,
                                )
                                for url, (proxy_url, proxy_type) in zip(urls, proxy_data, strict=False)
                            ]
                        )
                    )
                else:
                    return list(
                        await asyncio.gather(
                            *[AsyncFetcher.fetch(session, url, params, json, include_metadata=include_metadata) for url in urls]
                        )
                    )


def show_default_error_message(engine_name: str, word: str, error) -> None:
    output_logger.info(f"Failed to process {engine_name} search for word: '{word}'")
    output_logger.info(f'Error Message: {error}')
