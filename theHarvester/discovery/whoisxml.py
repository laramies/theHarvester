from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchWhoisXML:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.whoisxml_key()
        if self.key is None:
            raise MissingKey('whoisxml')
        self.total_results = None
        self.proxy = False

    async def do_search(self):
        # https://subdomains.whoisxmlapi.com/api/documentation/making-requests
        url = 'https://subdomains.whoisxmlapi.com/api/v1'
        params = {'apiKey': self.key, 'domainName': self.word}
        response = await AsyncFetcher.fetch_all(
            [url],
            json=True,
            params=params,
            headers={'User-Agent': Core.get_user_agent()},
            proxy=self.proxy,
        )
        # Parse the response according to the example JSON structure:
        # {"search":"example.com.com","result":{"count":10000,"records":[{"domain":"test.example.com","firstSeen":1678169400,"lastSeen":1678169400}]}}
        self.total_results = []
        print(response[0])
        if response and response[0]:
            # Extract domains from the records array
            if 'result' in response[0] and 'records' in response[0]['result']:
                self.total_results = [record['domain'] for record in response[0]['result']['records']]

    async def get_hostnames(self):
        return self.total_results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
