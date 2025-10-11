import re
from typing import Any

from theHarvester.lib.core import AsyncFetcher


class SearchOtx:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.word}/passive_dns'
        try:
            response_list = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        except (OSError, RuntimeError, ValueError):
            self.totalhosts = set()
            self.totalips = set()
            return

        # Expect a list with one JSON-decoded dict
        dct: Any = response_list[0] if response_list else {}
        if not isinstance(dct, dict):
            self.totalhosts = set()
            self.totalips = set()
            return

        passive = dct.get('passive_dns')
        if not isinstance(passive, list):
            self.totalhosts = set()
            self.totalips = set()
            return

        try:
            self.totalhosts = {host['hostname'] for host in passive if isinstance(host, dict) and 'hostname' in host}
            # filter out ips that are just called NXDOMAIN and ensure they look like IPv4
            self.totalips = {
                ip['address']
                for ip in passive
                if isinstance(ip, dict)
                and (addr := ip.get('address'))
                and isinstance(addr, str)
                and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', addr)
            }
        except (KeyError, TypeError, ValueError):
            self.totalhosts = set()
            self.totalips = set()

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
