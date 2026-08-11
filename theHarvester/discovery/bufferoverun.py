import re

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchBufferover:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.key = Core.bufferoverun_key()
        if self.key is None:
            raise MissingKey('bufferoverun')
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://tls.bufferover.run/dns?q={self.word}'
        response = await AsyncFetcher.fetch_all(
            [url],
            json=True,
            headers={'User-Agent': Core.get_user_agent(), 'x-api-key': f'{self.key}'},
            proxy=self.proxy,
        )
        dct = response[0]
        if not dct or not dct.get('Results'):
            return

        # Each entry is formatted as '<ip>,<sha256>,<cert-org>,<CN/SNI>', so the
        # hostname is the last field. The certificate organization may itself
        # contain commas, hence the right-split.
        self.totalhosts = {hostname.strip() for host in dct['Results'] if (hostname := host.rsplit(',', 1)[-1].strip())}

        self.totalips = {
            ip.split(',')[0] for ip in dct['Results'] if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip.split(',')[0])
        }

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
