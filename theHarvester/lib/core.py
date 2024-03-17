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

from .version import version

if TYPE_CHECKING:
    from collections.abc import Sized

DATA_DIR = Path(__file__).parents[1] / 'data'
CONFIG_DIRS = [
    Path('/etc/theHarvester/'),
    Path('/usr/local/etc/theHarvester/'),
    Path('~/.theHarvester'),
]


class Core:
    @staticmethod
    def _read_config(filename: str) -> str:
        # Return the first we find
        for path in CONFIG_DIRS:
            with contextlib.suppress(FileNotFoundError):
                file = path.expanduser() / filename
                config = file.read_text()
                print(f'Read {filename} from {file}')
                return config

        # Fallback to creating default in user's home dir
        default = (DATA_DIR / filename).read_text()
        dest = CONFIG_DIRS[-1].expanduser() / filename
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
    def binaryedge_key() -> str:
        return Core.api_keys()['binaryedge']['key']

    @staticmethod
    def bing_key() -> str:
        return Core.api_keys()['bing']['key']

    @staticmethod
    def bufferoverun_key() -> str:
        return Core.api_keys()['bufferoverun']['key']

    @staticmethod
    def censys_key() -> tuple:
        return Core.api_keys()['censys']['id'], Core.api_keys()['censys']['secret']

    @staticmethod
    def criminalip_key() -> str:
        return Core.api_keys()['criminalip']['key']

    @staticmethod
    def fullhunt_key() -> str:
        return Core.api_keys()['fullhunt']['key']

    @staticmethod
    def github_key() -> str:
        return Core.api_keys()['github']['key']

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
    def netlas_key() -> str:
        return Core.api_keys()['netlas']['key']

    @staticmethod
    def pentest_tools_key() -> str:
        return Core.api_keys()['pentestTools']['key']

    @staticmethod
    def onyphe_key() -> str:
        return Core.api_keys()['onyphe']['key']

    @staticmethod
    def projectdiscovery_key() -> str:
        return Core.api_keys()['projectDiscovery']['key']

    @staticmethod
    def rocketreach_key() -> str:
        return Core.api_keys()['rocketreach']['key']

    @staticmethod
    def security_trails_key() -> str:
        return Core.api_keys()['securityTrails']['key']

    @staticmethod
    def shodan_key() -> str:
        return Core.api_keys()['shodan']['key']

    @staticmethod
    def zoomeye_key() -> str:
        return Core.api_keys()['zoomeye']['key']

    @staticmethod
    def tomba_key() -> tuple[str, str]:
        return Core.api_keys()['tomba']['key'], Core.api_keys()['tomba']['secret']

    @staticmethod
    def virustotal_key() -> str:
        return Core.api_keys()['virustotal']['key']

    @staticmethod
    def proxy_list() -> list:
        keys = yaml.safe_load(Core._read_config('proxies.yaml'))
        http_list = [f'http://{proxy}' for proxy in keys['http']] if keys['http'] is not None else []
        return http_list

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
    def get_supportedengines() -> list[str | Any]:
        supportedengines = [
            'anubis',
            'baidu',
            'bevigil',
            'binaryedge',
            'bing',
            'bingapi',
            'bufferoverun',
            'brave',
            'censys',
            'certspotter',
            'criminalip',
            'crtsh',
            'dnsdumpster',
            'duckduckgo',
            'fullhunt',
            'github-code',
            'hackertarget',
            'hunter',
            'hunterhow',
            'intelx',
            'netlas',
            'onyphe',
            'otx',
            'pentesttools',
            'projectdiscovery',
            'rapiddns',
            'rocketreach',
            'securityTrails',
            'sitedossier',
            'subdomaincenter',
            'subdomainfinderc99',
            'threatminer',
            'tomba',
            'urlscan',
            'virustotal',
            'yahoo',
            'zoomeye',
        ]
        return supportedengines

    @staticmethod
    def get_user_agent() -> str:
        # User-Agents from https://techblog.willshouse.com/2012/01/03/most-common-user-agents/
        # Lasted updated 7/2/23
        # TODO use bs4 to auto parse user agents
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Mozilla/5.0 (Windows NT 10.0; rv:114.0) Gecko/20100101 Firefox/114.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.43',
            'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 OPR/99.0.0.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/113.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.37',
            'Mozilla/5.0 (Windows NT 10.0; rv:113.0) Gecko/20100101 Firefox/113.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.57',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.41',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 OPR/98.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 YaBrowser/23.5.2.625 Yowser/2.5 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0',
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Linux; Android 7.0; Moto G (4)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4590.2 Mobile Safari/537.36 Chrome-Lighthouse',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        ]
        return random.choice(user_agents)


class AsyncFetcher:
    proxy_list = Core.proxy_list()

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
                proxy = random.choice(cls().proxy_list)
                if params != '':
                    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                        async with session.get(url, params=params, proxy=proxy) as response:
                            await asyncio.sleep(5)
                            return await response.text() if json is False else await response.json()
                else:
                    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                        async with session.get(url, proxy=proxy) as response:
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
        except Exception as e:
            print(f'An exception has occurred in post_fetch: {e}')
            return ''

    @classmethod
    async def fetch(cls, session, url, params: Sized = '', json: bool = False, proxy: str = '') -> str | dict | list | bool:
        # This fetch method solely focuses on get requests
        try:
            # Wrap in try except due to 0x89 png/jpg files
            # This fetch method solely focuses on get requests
            if proxy != '':
                proxy = str(random.choice(cls().proxy_list))
                if len(params) != 0:
                    sslcontext = ssl.create_default_context(cafile=certifi.where())
                    async with session.get(url, ssl=sslcontext, params=params, proxy=proxy) as response:
                        return await response.text() if json is False else await response.json()
                else:
                    sslcontext = ssl.create_default_context(cafile=certifi.where())
                    async with session.get(url, ssl=sslcontext, proxy=proxy) as response:
                        await asyncio.sleep(5)
                        return await response.text() if json is False else await response.json()

            if len(params) != 0:
                sslcontext = ssl.create_default_context(cafile=certifi.where())
                async with session.get(url, ssl=sslcontext, params=params) as response:
                    await asyncio.sleep(5)
                    return await response.text() if json is False else await response.json()

            else:
                sslcontext = ssl.create_default_context(cafile=certifi.where())
                async with session.get(url, ssl=sslcontext) as response:
                    await asyncio.sleep(5)
                    return await response.text() if json is False else await response.json()
        except Exception as e:
            print(f'An exception has occurred: {e}')
            return ''

    @staticmethod
    async def takeover_fetch(session, url: str, proxy: str = '') -> tuple[Any, Any] | str:
        # This fetch method solely focuses on get requests
        try:
            # Wrap in try except due to 0x89 png/jpg files
            # This fetch method solely focuses on get requests
            # TODO determine if method for post requests is necessary
            # url = f'http://{url}' if str(url).startswith(('http:', 'https:')) is False else url
            # Clean up urls with proper schemas
            if proxy != '':
                if 'https://' in url:
                    sslcontext = ssl.create_default_context(cafile=certifi.where())
                    async with session.get(url, proxy=proxy, ssl=sslcontext) as response:
                        await asyncio.sleep(5)
                        return url, await response.text()
                else:
                    async with session.get(url, proxy=proxy, ssl=False) as response:
                        await asyncio.sleep(5)
                        return url, await response.text()
            else:
                if 'https://' in url:
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
                    return await asyncio.gather(
                        *[AsyncFetcher.takeover_fetch(session, url, proxy=random.choice(cls().proxy_list)) for url in urls]
                    )
                else:
                    return await asyncio.gather(*[AsyncFetcher.takeover_fetch(session, url) for url in urls])

        if len(params) == 0:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout, max_field_size=13000) as session:
                if proxy:
                    return await asyncio.gather(
                        *[
                            AsyncFetcher.fetch(
                                session,
                                url,
                                json=json,
                                proxy=random.choice(cls().proxy_list),
                            )
                            for url in urls
                        ]
                    )
                else:
                    return await asyncio.gather(*[AsyncFetcher.fetch(session, url, json=json) for url in urls])
        else:
            # Indicates the request has certain params
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                if proxy:
                    return await asyncio.gather(
                        *[
                            AsyncFetcher.fetch(
                                session,
                                url,
                                params,
                                json,
                                proxy=random.choice(cls().proxy_list),
                            )
                            for url in urls
                        ]
                    )
                else:
                    return await asyncio.gather(*[AsyncFetcher.fetch(session, url, params, json) for url in urls])
