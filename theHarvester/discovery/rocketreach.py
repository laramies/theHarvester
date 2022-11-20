from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from typing import Set
import asyncio


class SearchRocketReach:

    def __init__(self, word, limit) -> None:
        self.ips: Set = set()
        self.word = word
        self.key = Core.rocketreach_key()
        if self.key is None:
            raise MissingKey('RocketReach')
        self.hosts: Set = set()
        self.proxy = False
        self.baseurl = 'https://api.rocketreach.co/v2/api/search'
        self.links: Set = set()
        self.limit = limit

    async def do_search(self) -> None:
        try:
            headers = {
                'Api-Key': self.key,
                'Content-Type': 'application/json',
                'User-Agent': Core.get_user_agent()
            }

            next_page = 1  # track pagniation
            for count in range(1, self.limit):
                data = f'{{"query":{{"company_domain": ["{self.word}"]}}, "start": {next_page}, "page_size": 100}}'
                result = await AsyncFetcher.post_fetch(self.baseurl, headers=headers, data=data, json=True)
                if 'detail' in result.keys() and 'error' in result.keys() and 'Subscribe to a plan to access' in result['detail']:
                    # No more results can be fetched
                    break
                if 'detail' in result.keys() and 'Request was throttled.' in result['detail']:
                    # Rate limit has been triggered need to sleep extra
                    print(f'RocketReach requests have been throttled; '
                          f'{result["detail"].split(" ", 3)[-1].replace("available", "availability")}')
                    break
                if 'profiles' in dict(result).keys():
                    if len(result['profiles']) == 0:
                        break
                    for profile in result['profiles']:
                        if 'linkedin_url' in dict(profile).keys():
                            self.links.add(profile['linkedin_url'])
                if 'pagination' in dict(result).keys():
                    next_page = int(result['pagination']['next'])
                    if next_page > int(result['pagination']['total']):
                        break

            await asyncio.sleep(get_delay() + 2)

        except Exception as e:
            print(f'An exception has occurred: {e}')

    async def get_links(self):
        return self.links

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
