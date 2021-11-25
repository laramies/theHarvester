# coding=utf-8

from typing import Set, Union, Any, Tuple, List
import yaml
import asyncio
import aiohttp
import random
import ssl
import certifi


class Core:
    @staticmethod
    def version() -> str:
        return '4.0.3'

    @staticmethod
    def api_keys() -> dict:
        try:
            with open('/etc/theHarvester/api-keys.yaml', 'r') as api_keys:
                keys = yaml.safe_load(api_keys)
        except FileNotFoundError:
            try:
                with open('/usr/local/etc/theHarvester/api-keys.yaml', 'r') as api_keys:
                    keys = yaml.safe_load(api_keys)
            except FileNotFoundError:
                with open('api-keys.yaml', 'r') as api_keys:
                    keys = yaml.safe_load(api_keys)
        return keys['apikeys']

    @staticmethod
    def binaryedge_key() -> str:
        return Core.api_keys()['binaryedge']['key']

    @staticmethod
    def bing_key() -> str:
        return Core.api_keys()['bing']['key']

    @staticmethod
    def censys_key() -> tuple:
        return Core.api_keys()['censys']['id'], Core.api_keys()['censys']['secret']

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
    def intelx_key() -> str:
        return Core.api_keys()['intelx']['key']

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
    def security_trails_key() -> str:
        return Core.api_keys()['securityTrails']['key']

    @staticmethod
    def shodan_key() -> str:
        return Core.api_keys()['shodan']['key']

    @staticmethod
    def spyse_key() -> str:
        return Core.api_keys()['spyse']['key']

    @staticmethod
    def zoomeye_key() -> str:
        return Core.api_keys()['zoomeye']['key']

    @staticmethod
    def proxy_list() -> List:
        try:
            with open('/etc/theHarvester/proxies.yaml', 'r') as proxy_file:
                keys = yaml.safe_load(proxy_file)
        except FileNotFoundError:
            try:
                with open('/usr/local/etc/theHarvester/proxies.yaml', 'r') as proxy_file:
                    keys = yaml.safe_load(proxy_file)
            except FileNotFoundError:
                with open('proxies.yaml', 'r') as proxy_file:
                    keys = yaml.safe_load(proxy_file)
        http_list = [f'http://{proxy}' for proxy in keys['http']] if keys['http'] is not None else []
        return http_list

    @staticmethod
    def banner() -> None:
        print('\n\033[93m*******************************************************************')
        print("*  _   _                                            _             *")
        print(r"* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *")
        print(r"* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *")
        print(r"* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *")
        print(r"*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *")
        print('*                                                                 *')
        print(
            '* theHarvester {version}{filler}*'.format(version=Core.version(), filler=' ' * (51 - len(Core.version()))))
        print('* Coded by Christian Martorella                                   *')
        print('* Edge-Security Research                                          *')
        print('* cmartorella@edge-security.com                                   *')
        print('*                                                                 *')
        print('******************************************************************* \n\n\033[0m')

    @staticmethod
    def get_supportedengines() -> Set[Union[str, Any]]:
        supportedengines = {'anubis',
                            'baidu',
                            'binaryedge',
                            'bing',
                            'bingapi',
                            'bufferoverun',
                            'censys',
                            'certspotter',
                            'crtsh',
                            'dnsdumpster',
                            'duckduckgo',
                            'fullhunt',
                            'github-code',
                            'google',
                            'hackertarget',
                            'hunter',
                            'intelx',
                            'linkedin',
                            'linkedin_links',
                            'n45ht',
                            'omnisint',
                            'otx',
                            'pentesttools',
                            'projectdiscovery',
                            'qwant',
                            'rapiddns',
                            'rocketreach',
                            'securityTrails',
                            'sublist3r',
                            'spyse',
                            'threatcrowd',
                            'threatminer',
                            'trello',
                            'twitter',
                            'urlscan',
                            'virustotal',
                            'yahoo',
                            'zoomeye'
                            }
        return supportedengines

    @staticmethod
    def get_user_agent() -> str:
        # User-Agents from https://techblog.willshouse.com/2012/01/03/most-common-user-agents/
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:93.0) Gecko/20100101 Firefox/93.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 OPR/80.0.4170.63",
            "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 Edg/95.0.1020.44",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 Edg/95.0.1020.53",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/95.0.1020.40",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/95.0.1020.30",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
            "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 Edg/94.0.992.50",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 OPR/80.0.4170.63 (Edition Yx 05)",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 YaBrowser/21.9.2.169 Yowser/2.5 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
            "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 OPR/80.0.4170.91",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:93.0) Gecko/20100101 Firefox/93.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36"]
        return random.choice(user_agents)


class AsyncFetcher:
    proxy_list = Core.proxy_list()

    @classmethod
    async def post_fetch(cls, url, headers='', data='', params='', json=False, proxy=False):
        if len(headers) == 0:
            headers = {'User-Agent': Core.get_user_agent()}
        timeout = aiohttp.ClientTimeout(total=720)
        # by default timeout is 5 minutes, changed to 12 minutes
        # results are well worth the wait
        try:
            if proxy:
                proxy = str(random.choice(cls().proxy_list))
                if params != "":
                    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                        async with session.get(url, params=params, proxy=proxy) as response:
                            await asyncio.sleep(2)
                            return await response.text() if json is False else await response.json()
                else:
                    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                        async with session.get(url, proxy=proxy) as response:
                            await asyncio.sleep(2)
                            return await response.text() if json is False else await response.json()
            elif params == '':
                async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                    async with session.post(url, data=data) as resp:
                        await asyncio.sleep(3)
                        return await resp.text() if json is False else await resp.json()
            else:
                async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                    sslcontext = ssl.create_default_context(cafile=certifi.where())
                    async with session.post(url, data=data, ssl=sslcontext, params=params) as resp:
                        await asyncio.sleep(3)
                        return await resp.text() if json is False else await resp.json()
        except Exception as e:
            print(f'An exception has occurred: {e}')
            return ''

    @staticmethod
    async def fetch(session, url, params='', json=False, proxy="") -> Union[str, dict, list, bool]:
        # This fetch method solely focuses on get requests
        try:
            # Wrap in try except due to 0x89 png/jpg files
            # This fetch method solely focuses on get requests
            # TODO determine if method for post requests is necessary
            if proxy != "":
                if params != "":
                    sslcontext = ssl.create_default_context(cafile=certifi.where())
                    async with session.get(url, ssl=sslcontext, params=params, proxy=proxy) as response:
                        return await response.text() if json is False else await response.json()
                else:
                    sslcontext = ssl.create_default_context(cafile=certifi.where())
                    async with session.get(url, ssl=sslcontext, proxy=proxy) as response:
                        await asyncio.sleep(2)
                        return await response.text() if json is False else await response.json()

            if params != '':
                sslcontext = ssl.create_default_context(cafile=certifi.where())
                async with session.get(url, ssl=sslcontext, params=params) as response:
                    await asyncio.sleep(2)
                    return await response.text() if json is False else await response.json()

            else:
                sslcontext = ssl.create_default_context(cafile=certifi.where())
                async with session.get(url, ssl=sslcontext) as response:
                    await asyncio.sleep(2)
                    return await response.text() if json is False else await response.json()
        except Exception as e:
            print(f'An exception has occurred: {e}')
            return ''

    @staticmethod
    async def takeover_fetch(session, url, proxy="") -> Union[Tuple[Any, Any], str]:
        # This fetch method solely focuses on get requests
        try:
            # Wrap in try except due to 0x89 png/jpg files
            # This fetch method solely focuses on get requests
            # TODO determine if method for post requests is necessary
            url = f'http://{url}' if str(url).startswith(('http:', 'https:')) is False else url
            # Clean up urls with proper schemas
            if proxy != "":
                async with session.get(url, proxy=proxy) as response:
                    await asyncio.sleep(2)
                    return url, await response.text()
            else:
                async with session.get(url) as response:
                    await asyncio.sleep(2)
                    return url, await response.text()
        except Exception:
            return url, ''

    @classmethod
    async def fetch_all(cls, urls, headers='', params='', json=False, takeover=False, proxy=False) -> list:
        # By default timeout is 5 minutes, 60 seconds should suffice
        timeout = aiohttp.ClientTimeout(total=60)
        if len(headers) == 0:
            headers = {'User-Agent': Core.get_user_agent()}
        if takeover:
            async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as session:
                if proxy:
                    tuples = await asyncio.gather(
                        *[AsyncFetcher.takeover_fetch(session, url, proxy=random.choice(cls().proxy_list)) for url in
                          urls])
                    return tuples
                else:
                    tuples = await asyncio.gather(*[AsyncFetcher.takeover_fetch(session, url) for url in urls])
                    return tuples

        if len(params) == 0:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                if proxy:
                    texts = await asyncio.gather(
                        *[AsyncFetcher.fetch(session, url, json=json, proxy=random.choice(cls().proxy_list)) for url in
                          urls])
                    return texts
                else:
                    texts = await asyncio.gather(*[AsyncFetcher.fetch(session, url, json=json) for url in urls])
                    return texts
        else:
            # Indicates the request has certain params
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                if proxy:
                    texts = await asyncio.gather(*[AsyncFetcher.fetch(session, url, params, json,
                                                                      proxy=random.choice(cls().proxy_list)) for url in
                                                   urls])
                    return texts
                else:
                    texts = await asyncio.gather(*[AsyncFetcher.fetch(session, url, params, json) for url in urls])
                    return texts
