from theHarvester.lib.core import *
import re


class SearchOtx:
    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.totalips = set()

    async def do_search(self):
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.word}/passive_dns'
        headers = {'User-Agent': Core.get_user_agent()}
        client = aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=20))
        responses = await AsyncFetcher.fetch(client, url, json=True)
        await client.close()
        dct = responses
        import pprint as p
        # p.pprint(dct, indent=4)
        # exit(-2)
        self.totalhosts: set = {host['hostname'] for host in dct['passive_dns']}
        # filter out ips that are just called NXDOMAIN
        self.totalips: set = {ip['address'] for ip in dct['passive_dns']
                              if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip['address'])}

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self):
        await self.do_search()


async def main():
    x = SearchOtx(word="yale.edu")
    await x.do_search()


if __name__ == '__main__':
    import asyncio

    asyncio.run(main())
