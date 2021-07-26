from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
import json


class SearchSpyse:

    def __init__(self, word, limit):
        self.ips = set()
        self.word = word
        self.key = Core.spyse_key()
        if self.key is None:
            raise MissingKey('Spyse')
        self.results = ''
        self.hosts = set()
        self.proxy = False
        self.limit = limit

    async def do_search(self):
        # Spyse allows to get up to 100 results per one request
        max_limit = 100
        # Spyse "search" methods allows to fetch up to 10 000 first results
        max_offset = 9900
        offset = 0

        while True:
            try:
                headers = {
                    'accept': 'application/json',
                    'Authorization': f'Bearer {self.key}',
                }

                base_url = 'https://api.spyse.com/v4/data/domain/search'

                query = {
                    'search_params': [
                        {
                            'name': {
                                'operator': 'ends',
                                'value': '.' + self.word,
                            }
                        }
                    ],
                    'limit': max_limit if self.limit > max_limit else self.limit,
                    'offset': offset,
                }

                results = await AsyncFetcher.post_fetch(base_url, json=True, headers=headers, data=json.dumps(query))

                if len(results.get('data').get('items')) > 0:
                    for domain in results['data']['items']:
                        self.hosts.add(domain['name'])

                else:
                    break

                offset += max_limit
                if offset > max_offset or offset + max_limit > self.limit:
                    break

            except Exception as e:
                print(f'An exception has occurred: {e}')

    async def get_hostnames(self):
        return self.hosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
