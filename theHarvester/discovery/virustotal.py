from theHarvester.discovery.constants import *
from theHarvester.lib.core import *


class SearchVirustotal:

    def __init__(self, word) -> None:
        self.key = Core.virustotal_key()
        if self.key is None:
            raise MissingKey('virustotal')
        self.word = word
        self.proxy = False
        self.hostnames: List = []

    async def do_search(self) -> None:
        # TODO determine if more endpoints can yield useful info given a domain
        # based on: https://developers.virustotal.com/reference/domains-relationships
        # base_url = "https://www.virustotal.com/api/v3/domains/domain/subdomains?limit=40"
        headers = {
            'User-Agent': Core.get_user_agent(),
            "Accept": "application/json",
            "x-apikey": self.key
        }
        base_url = f"https://www.virustotal.com/api/v3/domains/{self.word}/subdomains?limit=40"
        cursor = ''
        count = 0
        fail_counter = 0
        counter = 0
        breakcon = False
        while True:
            if breakcon:
                break
            # rate limit is 4 per minute
            # TODO add timer logic if proven to be needed
            # in the meantime sleeping 16 seconds should eliminate hitting the rate limit
            # in case rate limit is hit, fail counter exists and sleep for 65 seconds
            send_url = base_url + "&cursor=" + cursor if cursor != '' and len(cursor) > 2 else base_url
            responses = await AsyncFetcher.fetch_all([send_url], headers=headers, proxy=self.proxy, json=True)
            jdata = responses[0]
            if 'data' not in jdata.keys():
                await asyncio.sleep(60 + 5)
                fail_counter += 1
            if 'meta' in jdata.keys():
                cursor = jdata['meta']['cursor'] if 'cursor' in jdata['meta'].keys() else ''
                if len(cursor) == 0 and 'data' in jdata.keys():
                    # if cursor no longer is within the meta field have hit last entry
                    breakcon = True
            count += jdata['meta']['count']
            if count == 0 or fail_counter >= 2:
                break
            if 'data' in jdata.keys():
                data = jdata['data']
                self.hostnames.extend(await self.parse_hostnames(data, self.word))
                counter += 1
            await asyncio.sleep(16)
        self.hostnames = list(sorted(set(self.hostnames)))
        # verify domains such as x.x.com.multicdn.x.com are parsed properly
        self.hostnames = [host for host in self.hostnames if ((len(host.split('.')) >= 3) and host.split('.')[-2] == self.word.split('.')[-2])]

    async def get_hostnames(self) -> list:
        return self.hostnames

    @staticmethod
    async def parse_hostnames(data, word):
        total_subdomains = set()
        for attribute in data:
            total_subdomains.add(attribute['id'].replace('"', '').replace('www.', ''))
            attributes = attribute['attributes']
            total_subdomains.update(
                {value['value'].replace('"', '').replace('www.', '') for value in attributes['last_dns_records'] if
                 word in value['value']})
            if 'last_https_certificate' in attributes.keys():
                total_subdomains.update({value.replace('"', '').replace('www.', '') for value in
                                         attributes['last_https_certificate']['extensions']['subject_alternative_name']
                                         if word in value})
        total_subdomains = list(sorted(total_subdomains))
        # Other false positives may occur over time and yes there are other ways to parse this, feel free to implement
        # them and submit a PR or raise an issue if you run into this filtering not being enough
        # TODO determine if parsing 'v=spf1 include:_spf-x.acme.com include:_spf-x.acme.com' is worth parsing
        total_subdomains = [x for x in total_subdomains if not str(x).endswith('edgekey.net') and not str(x).endswith(
            'akadns.net') and 'include:_spf' not in str(x)]
        total_subdomains.sort()
        return total_subdomains

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
