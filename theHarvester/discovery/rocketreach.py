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
        self.baseurl = 'https://api.rocketreach.co/api/v2/person/search'
        self.links: set = set()
        self.emails: set = set()
        self.limit = limit

    async def do_search(self) -> None:
        try:
            if self.limit <= 0:
                return

            headers = {
                'Api-Key': self.key,
                'Content-Type': 'application/json',
                'User-Agent': Core.get_user_agent(),
            }

            start = 0
            remaining = self.limit
            while remaining > 0:
                page_size = min(100, remaining)
                data = {
                    'query': {'current_employer_domain': [self.word]},
                    'start': start,
                    'page_size': page_size,
                }
                result = await AsyncFetcher.post_fetch(self.baseurl, headers=headers, data=data, json=True)
                if not isinstance(result, dict):
                    break

                detail = result.get('detail', '')
                if detail and 'Subscribe to a plan to access' in str(detail):
                    # No more results can be fetched
                    break

                if detail and 'Request was throttled.' in str(detail):
                    # Rate limit has been triggered need to sleep extra
                    print(
                        f'RocketReach requests have been throttled; '
                        f'{str(detail).split(" ", 3)[-1].replace("available", "availability")}'
                    )
                    break

                profiles = result.get('profiles', [])
                if not profiles:
                    break

                for profile in profiles:
                    if 'linkedin_url' in profile:
                        self.links.add(profile['linkedin_url'])
                    if 'emails' in profile and profile['emails']:
                        for email in profile['emails']:
                            if email.get('email'):
                                self.emails.add(email['email'])

                found = len(profiles)
                remaining -= found
                start += found

                pagination = result.get('pagination', {})
                total = pagination.get('total')
                if isinstance(total, int) and start >= total:
                    break
                if found < page_size:
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
