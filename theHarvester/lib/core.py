from __future__ import annotations

import asyncio
import contextlib
import random
import ssl
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp
import certifi

# need to import as different name as to not shadow already existing json var in post_fetch
import ujson as json_loader
import yaml
from aiohttp_socks import ProxyConnector

from .version import version

if TYPE_CHECKING:
    from collections.abc import Sized

DATA_DIR = Path(__file__).parents[1] / 'data'
CONFIG_DIRS = [
    Path('~/.theHarvester'),
    Path('/etc/theHarvester/'),
    Path('/usr/local/etc/theHarvester/'),
]


class Core:
    quiet: bool = False

    @staticmethod
    def _read_config(filename: str) -> str:
        # Return the first we find
        for path in CONFIG_DIRS:
            with contextlib.suppress(FileNotFoundError):
                file = path.expanduser() / filename
                config = file.read_text()
                if not Core.quiet:
                    print(f'Read {filename} from {file}')
                return config

        # Fallback to creating default in the user's home dir
        default = (DATA_DIR / filename).read_text()
        dest = CONFIG_DIRS[0].expanduser() / filename
        dest.parent.mkdir(exist_ok=True)
        dest.write_text(default)
        print(f'Created default {filename} at {dest}')
        return default

    @staticmethod
    def api_keys() -> dict:
        keys = yaml.safe_load(Core._read_config('api-keys.yaml'))
        return keys['apikeys']

    @staticmethod
    def bevigil_key() -> str:
        return Core.api_keys()['bevigil']['key']

    @staticmethod
    def bitbucket_key() -> str:
        return Core.api_keys()['bitbucket']['key']

    @staticmethod
    def brave_key() -> str:
        return Core.api_keys()['brave']['key']

    @staticmethod
    def bufferoverun_key() -> str:
        return Core.api_keys()['bufferoverun']['key']

    @staticmethod
    def builtwith_key() -> str:
        return Core.api_keys()['builtwith']['key']

    @staticmethod
    def censys_key() -> tuple:
        return Core.api_keys()['censys']['id'], Core.api_keys()['censys']['secret']

    @staticmethod
    def criminalip_key() -> str:
        return Core.api_keys()['criminalip']['key']

    @staticmethod
    def dehashed_key() -> str:
        return Core.api_keys()['dehashed']['key']

    @staticmethod
    def dnsdumpster_key() -> str:
        return Core.api_keys()['dnsdumpster']['key']

    @staticmethod
    def fofa_key() -> tuple[str, str]:
        return Core.api_keys()['fofa']['key'], Core.api_keys()['fofa']['email']

    @staticmethod
    def fullhunt_key() -> str:
        return Core.api_keys()['fullhunt']['key']

    @staticmethod
    def github_key() -> str:
        return Core.api_keys()['github']['key']

    @staticmethod
    def hackertarget_key() -> str:
        return Core.api_keys()['hackertarget']['key']

    @staticmethod
    def haveibeenpwned_key() -> str:
        return Core.api_keys()['haveibeenpwned']['key']

    @staticmethod
    def hunter_key() -> str:
        return Core.api_keys()['hunter']['key']

    @staticmethod
    def hunterhow_key() -> str:
        return Core.api_keys()['hunterhow']['key']

    @staticmethod
    def intelx_key() -> str:
        return Core.api_keys()['intelx']['key']

    @staticmethod
    def leaklookup_key() -> str:
        return Core.api_keys()['leaklookup']['key']

    @staticmethod
    def leakix_key() -> str:
        return Core.api_keys()['leakix']['key']

    @staticmethod
    def netlas_key() -> str:
        return Core.api_keys()['netlas']['key']

    @staticmethod
    def onyphe_key() -> str:
        return Core.api_keys()['onyphe']['key']

    @staticmethod
    def pentest_tools_key() -> str:
        return Core.api_keys()['pentestTools']['key']

    @staticmethod
    def projectdiscovery_key() -> str:
        return Core.api_keys()['projectDiscovery']['key']

    @staticmethod
    def rocketreach_key() -> str:
        return Core.api_keys()['rocketreach']['key']

    @staticmethod
    def securityscorecard_key() -> str:
        return Core.api_keys()['securityscorecard']['key']

    @staticmethod
    def security_trails_key() -> str:
        return Core.api_keys()['securityTrails']['key']

    @staticmethod
    def shodan_key() -> str:
        return Core.api_keys()['shodan']['key']

    @staticmethod
    def tomba_key() -> tuple[str, str]:
        return Core.api_keys()['tomba']['key'], Core.api_keys()['tomba']['secret']

    @staticmethod
    def venacus_key() -> str:
        return Core.api_keys()['venacus']['key']

    @staticmethod
    def virustotal_key() -> str:
        return Core.api_keys()['virustotal']['key']

    @staticmethod
    def whoisxml_key() -> str:
        return Core.api_keys()['whoisxml']['key']

    @staticmethod
    def windvane_key() -> str:
        return Core.api_keys()['windvane']['key']

    @staticmethod
    def zoomeye_key() -> str:
        return Core.api_keys()['zoomeye']['key']

    @staticmethod
    def proxy_list() -> dict:
        keys = yaml.safe_load(Core._read_config('proxies.yaml'))
        http_list = [f'http://{proxy}' for proxy in keys['http']] if keys['http'] is not None else []
        socks5_list = [f'socks5://{proxy}' for proxy in keys['socks5']] if keys.get('socks5') is not None else []
        return {'http': http_list, 'socks5': socks5_list}

    @staticmethod
    def banner() -> None:
        print('*******************************************************************')
        print('*  _   _                                            _             *')
        print(r'* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *')
        print(r"* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *")
        print(r'* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *')
        print(r'*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *')
        print('*                                                                 *')
        print('* theHarvester {version}{filler}*'.format(version=version(), filler=' ' * (51 - len(version()))))
        print('* Coded by Christian Martorella                                   *')
        print('* Edge-Security Research                                          *')
        print('* cmartorella@edge-security.com                                   *')
        print('*                                                                 *')
        print('*******************************************************************')

    @staticmethod
    def get_supportedengines() -> list[str]:
        """
        Returns a list of supported search engines.
        """
        return [
            'baidu',
            'bevigil',
            'bitbucket',
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
            'dnsdumpster',
            'duckduckgo',
            'fofa',
            'fullhunt',
            'github-code',
            'gitlab',
            'hackertarget',
            'haveibeenpwned',
            'hudsonrock',
            'hunter',
            'hunterhow',
            'intelx',
            'leakix',
            'leaklookup',
            'linkedin',
            'linkedin_links',
            'netcraft',
            'netlas',
            'omnisint',
            'onyphe',
            'otx',
            'pentesttools',
            'projectdiscovery',
            'qwant',
            'rapiddns',
            'robtex',
            'rocketreach',
            'securityscorecard',
            'securityTrails',
            'shodan',
            'subdomaincenter',
            'subdomainfinderc99',
            'sublist3r',
            'thc',
            'threatcrowd',
            'tomba',
            'urlscan',
            'venacus',
            'virustotal',
            'waybackarchive',
            'whoisxml',
            'windvane',
            'yahoo',
            'zoomeye',
            'zoomeyeapi',
        ]

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
    proxy_list = Core.proxy_list()

    @staticmethod
    def _get_random_proxy(proxy_dict: dict) -> tuple[str | None, str | None]:
        """
        Get a random proxy from the proxy dictionary.
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
        """
        Create an appropriate connector for the given proxy type.
        Returns a connector that can be used with aiohttp.ClientSession.
        """
        if proxy_url and proxy_type == 'socks5':
            # Create SOCKS5 proxy connector using aiohttp-socks
            # ProxyConnector.from_url can handle socks5://host:port URLs
            connector = ProxyConnector.from_url(proxy_url, ssl=ssl_context)
            return connector
        else:
            # Use default TCP connector for HTTP proxies or no proxy
            return aiohttp.TCPConnector(ssl=ssl_context if ssl_context else ssl.create_default_context(cafile=certifi.where()))

    @classmethod
    async def post_fetch(
        cls,
        url,
        headers=None,
        data: str | dict[str, str] = '',
        params: str = '',
        json: bool = False,
        proxy: bool = False,
    ):
        if headers is None:
            headers = {}
        if len(headers) == 0:
            headers = {'User-Agent': Core.get_user_agent()}
        timeout = aiohttp.ClientTimeout(total=720)
        # By default, timeout is 5 minutes, changed to 12-minutes
        # results are well worth the wait
        try:
            if proxy:
                proxy_url, proxy_type = cls._get_random_proxy(cls().proxy_list)
                sslcontext = ssl.create_default_context(cafile=certifi.where())
                connector = await cls._create_connector(proxy_url, proxy_type, sslcontext)

                if params != '':
                    async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector) as session:
                        # For HTTP proxies, pass proxy parameter; for SOCKS5, connector handles it
                        proxy_param = proxy_url if proxy_type == 'http' else None
                        async with session.get(url, params=params, proxy=proxy_param) as response:
                            await asyncio.sleep(5)
                            return await response.text() if json is False else await response.json()
                else:
                    async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector) as session:
                        proxy_param = proxy_url if proxy_type == 'http' else None
                        async with session.get(url, proxy=proxy_param) as response:
                            await asyncio.sleep(5)
                            return await response.text() if json is False else await response.json()
            elif params == '':
                if isinstance(data, str):
                    data = json_loader.loads(data)
                async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                    async with session.post(url, data=data) as resp:
                        await asyncio.sleep(3)
                        return await resp.text() if json is False else await resp.json()
            else:
                if isinstance(data, str):
                    data = json_loader.loads(data)
                async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                    sslcontext = ssl.create_default_context(cafile=certifi.where())
                    async with session.post(url, data=data, ssl=sslcontext, params=params) as resp:
                        await asyncio.sleep(3)
                        return await resp.text() if json is False else await resp.json()
        except Exception:
            return ''

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
    ) -> Any:
        """
        Generic HTTP request helper.
        - If a session is not provided, one will be created and closed automatically.
        - Supports optional headers, method selection, proxy, ssl verification, redirects and timeout.
        - Returns response text or json depending on `json` flag.
        """
        try:
            # Prepare SSL argument
            ssl_arg: ssl.SSLContext | bool | None
            if verify is False:
                ssl_arg = False
            else:
                # default True or None -> verify
                ssl_arg = ssl.create_default_context(cafile=certifi.where())

            # Resolve proxy parameter
            proxy_url: str | None = None
            proxy_type: str | None = None
            if isinstance(proxy, str) and proxy != '':
                proxy_url = proxy
                proxy_type = 'socks5' if proxy_url.startswith('socks5://') else 'http'
            elif isinstance(proxy, bool) and proxy:
                try:
                    proxy_url, proxy_type = cls._get_random_proxy(cls().proxy_list)
                except Exception:
                    proxy_url = None
                    proxy_type = None

            # Prepare timeout
            client_timeout = aiohttp.ClientTimeout(total=request_timeout) if request_timeout else None

            # Use provided headers or default UA
            req_headers = headers if headers is not None else {'User-Agent': Core.get_user_agent()}

            # Decide whether we need to manage the session
            owns_session = session is None
            if owns_session:
                # Create connector based on proxy type
                connector = await cls._create_connector(proxy_url, proxy_type, ssl_arg) if proxy_url else None
                session = aiohttp.ClientSession(headers=req_headers, timeout=client_timeout, connector=connector)
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

                if request_timeout:
                    async with asyncio.timeout(request_timeout):
                        async with session.request(method.upper(), url, **request_kwargs) as response:
                            await asyncio.sleep(5)
                            return await response.text() if json is False else await response.json()
                else:
                    async with session.request(method.upper(), url, **request_kwargs) as response:
                        await asyncio.sleep(5)
                        return await response.text() if json is False else await response.json()
            finally:
                if owns_session:
                    await session.close()
        except Exception:
            return ''

    @staticmethod
    async def takeover_fetch(session, url: str, proxy: str | None = None) -> tuple[Any, Any] | str:
        # This fetch method solely focuses on get requests
        try:
            # Wrap in try except due to 0x89 png/jpg files
            # This fetch method solely focuses on get requests
            # TODO determine if method for post requests is necessary
            # url = f'http://{url}' if str(url).startswith(('http:', 'https:')) is False else url
            # Clean up urls with proper schemas
            if proxy:
                if 'https://' in url:
                    sslcontext = ssl.create_default_context(cafile=certifi.where())
                    async with session.get(url, proxy=proxy, ssl=sslcontext) as response:
                        await asyncio.sleep(5)
                        return url, await response.text()
                else:
                    async with session.get(url, proxy=proxy, ssl=False) as response:
                        await asyncio.sleep(5)
                        return url, await response.text()
            elif 'https://' in url:
                sslcontext = ssl.create_default_context(cafile=certifi.where())
                async with session.get(url, ssl=sslcontext) as response:
                    await asyncio.sleep(5)
                    return url, await response.text()
            else:
                async with session.get(url, ssl=False) as response:
                    await asyncio.sleep(5)
                    return url, await response.text()
        except Exception as e:
            print(f'Takeover check error: {e}')
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
    ) -> list:
        # By default, timeout is 5 minutes; 60 seconds should suffice
        if headers is None:
            headers = {}
        timeout = aiohttp.ClientTimeout(total=60)
        if len(headers) == 0:
            headers = {'User-Agent': Core.get_user_agent()}
        if takeover:
            async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as session:
                if proxy:
                    # Get random proxy for each URL
                    proxy_urls = [cls._get_random_proxy(cls().proxy_list)[0] for _ in urls]
                    return await asyncio.gather(
                        *[AsyncFetcher.takeover_fetch(session, url, proxy=proxy_url) for url, proxy_url in zip(urls, proxy_urls)]
                    )
                else:
                    return await asyncio.gather(*[AsyncFetcher.takeover_fetch(session, url) for url in urls])

        if len(params) == 0:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                if proxy:
                    # Get random proxy for each URL (returns tuple of proxy_url and proxy_type)
                    proxy_data = [cls._get_random_proxy(cls().proxy_list) for _ in urls]
                    return await asyncio.gather(
                        *[
                            AsyncFetcher.fetch(
                                session,
                                url,
                                json=json,
                                proxy=proxy_url,
                            )
                            for url, (proxy_url, proxy_type) in zip(urls, proxy_data)
                        ]
                    )
                else:
                    return await asyncio.gather(*[AsyncFetcher.fetch(session, url, json=json) for url in urls])
        else:
            # Indicates the request has certain params
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                if proxy:
                    proxy_data = [cls._get_random_proxy(cls().proxy_list) for _ in urls]
                    return await asyncio.gather(
                        *[
                            AsyncFetcher.fetch(
                                session,
                                url,
                                params,
                                json,
                                proxy=proxy_url,
                            )
                            for url, (proxy_url, proxy_type) in zip(urls, proxy_data)
                        ]
                    )
                else:
                    return await asyncio.gather(*[AsyncFetcher.fetch(session, url, params, json) for url in urls])


def show_default_error_message(engine_name: str, word: str, error) -> None:
    print(f"Failed to process {engine_name} search for word: '{word}'")
    print(f'Error Message: {error}')
