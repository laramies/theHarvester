import asyncio

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.core import AsyncFetcher, Core


class SearchRocketReach:
    def __init__(self, word, limit) -> None:
        self.ips: set = set()
        self.word = word
        self.key = Core.rocketreach_key()
        if self.key is None:
            raise MissingKey('RocketReach')
        self.hosts: set = set()
        self.proxy = False
        self.baseurl = 'https://rocketreach.co/api/v2/person/search'
        self.links: set = set()
        self.emails: set = set()
        self.limit = limit

    async def do_search(self) -> None:
        try:
            headers = {
                'Api-Key': self.key,
                'Content-Type': 'application/json',
                'User-Agent': Core.get_user_agent(),
            }

            next_page = 1  # track pagination
            for count in range(1, self.limit):
                data = f'{{"query":{{"current_employer_domain": ["{self.word}"]}}, "page": {next_page}, "page_size": 100}}'
                result = await AsyncFetcher.post_fetch(self.baseurl, headers=headers, data=data, json=True)
                if 'detail' in result.keys() and 'error' in result.keys() and 'Subscribe to a plan to access' in result['detail']:
                    # No more results can be fetched
                    break
                if 'detail' in result.keys() and 'Request was throttled.' in result['detail']:
                    # Rate limit has been triggered need to sleep extra
                    print(
                        f'RocketReach requests have been throttled; '
                        f'{result["detail"].split(" ", 3)[-1].replace("available", "availability")}'
                    )
                    break
                if 'profiles' in dict(result).keys():
                    if len(result['profiles']) == 0:
                        break
                    for profile in result['profiles']:
                        if 'linkedin_url' in dict(profile).keys():
                            self.links.add(profile['linkedin_url'])
                        if 'emails' in dict(profile).keys() and profile['emails']:
                            for email in profile['emails']:
                                if 'email' in email and email['email']:
                                    self.emails.add(email['email'])
                if 'pagination' in dict(result).keys():
                    next_page = result['pagination']['page'] + 1
                    if next_page > result['pagination']['total_pages']:
                        break

            await asyncio.sleep(get_delay() + 5)

        except Exception as e:
            print(f'An exception has occurred rocketreach: {e}')

    async def get_links(self):
        return self.links

    async def get_emails(self):
        return self.emails

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
