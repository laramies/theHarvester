import json

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchNetlas:
    def __init__(self, word, limit: int) -> None:
        self.word = word
        self.totalhosts: list = []
        self.totalips: list = []
        self.key = Core.netlas_key()
        self.limit = limit
        if self.key is None:
            raise MissingKey('netlas')
        self.proxy = False

    async def do_count(self) -> None:
        """Counts the total number of subdomains

        :return: None
        """
        api = f'https://app.netlas.io/api/domains_count/?q=*.{self.word}'
        headers = {'X-API-Key': self.key}
        response = await AsyncFetcher.fetch_all([api], json=True, headers=headers, proxy=self.proxy)
        amount_size = response[0]['count']
        self.limit = amount_size if amount_size < self.limit else self.limit

    async def do_search(self) -> None:
        """Download domains for query 'q' size of 'limit'

        :return: None
        """
        user_agent = Core.get_user_agent()
        url = 'https://app.netlas.io/api/domains/download/'

        payload = {
            'q': f'*.{self.word}',
            'fields': json.dumps(['domain']),  # Convert the list to a JSON string
            'source_type': 'include',
            'size': str(self.limit),  # Convert integer to string
            'type': 'json',
            'indice': json.dumps([0]),  # Convert the list to a JSON string
        }

        headers = {
            'X-API-Key': self.key,
            'User-Agent': user_agent,
        }
        response = await AsyncFetcher.post_fetch(url, data=payload, headers=headers, proxy=self.proxy)
        resp_json = json.loads(response)

        for data in resp_json:
            domain = data['data']['domain']
            self.totalhosts.append(domain)

    async def get_hostnames(self) -> list:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_count()
        await self.do_search()
