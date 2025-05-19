#!/usr/bin/env python3
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchDNSDumpster:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.dnsdumpster_key()
        if not self.key:
            raise MissingKey('DNSDumpster')
        self.hosts: set = set()
        self.ips: set = set()
        self.base_url = 'https://api.dnsdumpster.com'

    async def do_search(self) -> None:
        try:
            url = f'{self.base_url}/domain/{self.word}'
            headers = {'User-Agent': 'Mozilla/5.0 (theHarvester)', 'X-API-Key': self.key}

            response = await AsyncFetcher.fetch_all([url], headers=headers, json=True)
            data = response[0]

            if isinstance(data, dict):
                # Process A records
                for record in data.get('a', []):
                    host = record['host']
                    if host.endswith(self.word):
                        self.hosts.add(host)
                    for ip_info in record['ips']:
                        self.ips.add(ip_info['ip'])

                # Process NS records
                for record in data.get('ns', []):
                    host = record['host']
                    if host.endswith(self.word):
                        self.hosts.add(host)
                    for ip_info in record['ips']:
                        self.ips.add(ip_info['ip'])

        except Exception as e:
            print(f'Error occurred in DNSDumpster search: {e}')

    async def process(self, proxy: bool = False) -> None:
        await self.do_search()

    async def get_hostnames(self) -> set:
        return self.hosts

    async def get_ips(self) -> set:
        return self.ips
