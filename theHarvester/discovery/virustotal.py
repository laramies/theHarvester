import asyncio

from theHarvester.lib.core import *
from theHarvester.discovery.constants import *
from theHarvester.parsers import myparser
import re


class SearchVirustotal:

    def __init__(self, word):
        #
        # self.key = Core.virustotal_key()
        self.key = ''
        if self.key is None:
            raise MissingKey('virustotal')
        self.word = word
        self.results = ""
        self.quantity = '100'
        self.counter = 0
        self.proxy = False
        self.hostnames = []

    async def do_search(self):
        # base = ""
        # &cursor=sadad
        # based on: https://developers.virustotal.com/reference/domains-relationships
        # base_url = "https://www.virustotal.com/api/v3/domains/apple.com/subdomains?limit=40"
        #
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
            print(f'Inside loop current iteration: {counter} and cursor: {cursor}')
            # rate limit is 4 per minute
            # TODO add timer logic if proven to be needed
            # in the meantime sleeping 16 seconds should eliminate hitting the rate limit
            # incase rate limit is hit, fail counter exists and sleep for 65 seconds
            send_url = base_url + "&cursor=" + cursor if cursor != '' and len(cursor) > 2 else base_url
            print(f'my send_url: {send_url}')
            responses = await AsyncFetcher.fetch_all([send_url], headers=headers, proxy=self.proxy, json=True)
            jdata = responses[0]
            if 'data' not in jdata.keys():
                await asyncio.sleep(60 + 5)
                fail_counter += 1
            if 'meta' in jdata.keys():
                cursor = jdata['meta']['cursor'] if 'cursor' in jdata['meta'].keys() else ''
                print(f'Current cursor: {cursor} and printing jdata meta ')
                print(jdata['meta'])
                if len(cursor) == 0 and 'data' in jdata.keys():
                    # if cursor no longer is within the meta field have hit last entry
                    breakcon = True
            count += jdata['meta']['count']
            if count == 0 or fail_counter >= 2:
                break
            # if cursor == '' or count == 0 or fail_counter >= 2:
            #    break
            data = jdata['data']
            self.hostnames.extend(await self.get_hostnames(data, self.word))
            print(f'Current hostnames: {len(self.hostnames)} at {counter} and cursor: {cursor}')
            counter += 1
            await asyncio.sleep(16)
        self.hostnames = list(sorted(set(self.hostnames)))

    @staticmethod
    async def get_hostnames(data, word):
        total_subdomains = set()
        for attribute in data:
            total_subdomains.add(attribute['id'].replace('"', '').replace('www.', ''))
            attributes = attribute['attributes']
            # print(total_subdomains)
            # print(attribute.keys())
            # print(attributes.keys())
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
        # TODO  determine if parsing 'v=spf1 include:_spf-x.acme.com include:_spf-x.acme.com' is worth parsing
        total_subdomains = [x for x in total_subdomains if
                            not str(x).endswith('edgekey.net') and not str(x).endswith('akadns.net')
                            and 'include:_spf' not in str(x)]
        total_subdomains.sort()
        return total_subdomains

    async def process(self, proxy=False):
        self.proxy = proxy
        print('\tSearching results.')
        await self.do_search()


async def temp():
    import requests
    # &cursor=sadad
    # based on: https://developers.virustotal.com/reference/domains-relationships
    url = "https://www.virustotal.com/api/v3/domains/apple.com/subdomains?limit=40"

    headers = {
        "Accept": "application/json",
        "x-apikey": ""
    }

    response = requests.get(url, headers=headers)

async def main():
    try:
        x = SearchVirustotal(word='apple.com')
        await x.do_search()
        hostnames = x.hostnames
        print(f'Obtained a total of: {len(hostnames)}')
        import pprint as p
        p.pprint(hostnames, indent=4)
    except Exception as e:
        print(f'An exception has occurred: {e}')
        import traceback as t
        t.print_exc()

if __name__ == '__main__':

    asyncio.run(main())
    #subject_alternative_name, id, ca_information_access (parse subdomain), last_dns_records (value)
    import json

    # response = requests.get(url, headers=headers)

    #with open(r'temptwo.json', 'r') as fp:
    #    x = fp.read()
    #jdata = json.loads(x)

    #cursor_exists = False
    #cursor = ''
    #count = 0

    #
    # print(len(total_subdomains))
    # p.pprint(total_subdomains, indent=4)
    #i = 0

    #word = 'apple.com'

    # import pprint as p

    #'ade.apple.com.edgekey.net'
    #.akadns.net',
    # 'apple.com.edgekey.net',
    # 'apple.com.edgekey.net.globalredir.akadns.net',
