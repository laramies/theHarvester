from urllib.parse import urlparse

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core

# from theHarvester.parsers import myparser


class SearchOnyphe:
    def __init__(self, word) -> None:
        self.word = word
        self.response = ''
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.asns: set = set()
        self.key = Core.onyphe_key()
        if self.key is None:
            raise MissingKey('onyphe')
        self.proxy = False

    async def do_search(self) -> None:
        # https://www.onyphe.io/docs/apis/search
        # https://www.onyphe.io/search?q=domain%3Acharter.com&captcharesponse=j5cGT
        # base_url = f'https://www.onyphe.io/api/v2/search/?q=domain:domain:{self.word}'
        base_url = f'https://www.onyphe.io/api/v2/search/?q=domain:{self.word}'
        headers = {
            'User-Agent': Core.get_user_agent(),
            'Content-Type': 'application/json',
            'Authorization': f'bearer {self.key}',
        }
        response = await AsyncFetcher.fetch_all([base_url], json=True, headers=headers, proxy=self.proxy)
        self.response = response[0]
        await self.parse_onyphe_resp_json()

    async def parse_onyphe_resp_json(self):
        if isinstance(self.response, list):
            self.response = self.response[0]
        if not isinstance(self.response, dict):
            raise Exception(f'An exception has occurred {self.response} is not a dict')
        if self.response['text'] == 'Success':
            if 'results' in self.response.keys():
                for result in self.response['results']:
                    try:
                        if 'alternativeip' in result.keys():
                            self.totalips.update({altip for altip in result['alternativeip']})
                        if 'url' in result.keys() and isinstance(result['url'], list):
                            self.totalhosts.update(
                                urlparse(url).netloc for url in result['url'] if urlparse(url).netloc.endswith(self.word)
                            )
                        self.asns.add(result['asn'])
                        self.asns.add(result['geolocus']['asn'])
                        self.totalips.add(result['geolocus']['subnet'])
                        self.totalips.add(result['ip'])
                        self.totalips.add(result['subnet'])
                        # Shouldn't be needed as API autoparses urls from html raw data
                        # rawres = myparser.Parser(result['data'], self.word)
                        # if await rawres.hostnames():
                        #     self.totalhosts.update(set(await rawres.hostnames()))
                        for subdomain_key in [
                            'domain',
                            'hostname',
                            'subdomains',
                            'subject',
                            'reverse',
                            'geolocus',
                        ]:
                            if subdomain_key in result.keys():
                                if subdomain_key == 'subject':
                                    self.totalhosts.update(
                                        {domain for domain in result[subdomain_key]['altname'] if domain.endswith(self.word)}
                                    )
                                elif subdomain_key == 'geolocus':
                                    self.totalhosts.update(
                                        {domain for domain in result[subdomain_key]['domain'] if domain.endswith(self.word)}
                                    )
                                else:
                                    self.totalhosts.update(
                                        {domain for domain in result[subdomain_key] if domain.endswith(self.word)}
                                    )
                    except Exception:
                        continue
        else:
            print(f'Onhyphe API query did not succeed dumping current response: {self.response}')

    async def get_asns(self) -> set:
        return self.asns

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
