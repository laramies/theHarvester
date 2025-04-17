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
    def whoisxml_key() -> str:
        return Core.api_keys()['whoisxml']['key']

    @staticmethod
    def venacus_key() -> str:
        return Core.api_keys()['venacus']['key']

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
            'bing',
            'bingapi',
            'bufferoverun',
            'brave',
            'censys',
            'certspotter',
            'criminalip',
            'crtsh',
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
            'whoisxml',
            'yahoo',
            'zoomeye',
            'venacus',
        ]
        return supportedengines

    @staticmethod
    def get_user_agent() -> str:
        # User-Agents from https://techblog.willshouse.com/2012/01/03/most-common-user-agents/
        # Lasted updated 3/30/25
        # TODO use bs4 to auto parse user agents
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 YaBrowser/25.2.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',
            'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.3',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
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
                        async with session.get(url, params=params, proxy=str(proxy) if proxy else None) as response:
                            await asyncio.sleep(5)
                            return await response.text() if json is False else await response.json()
                else:
                    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                        async with session.get(url, proxy=str(proxy) if proxy else None) as response:
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
        # Wrap in try except due to 0x89 png/jpg files
        try:
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
