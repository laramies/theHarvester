from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchDnsDumpster:
    def __init__(self, word: str) -> None:
        """
        Initialize the SearchDnsDumpster class with the target domain and initialize the necessary attributes.
        """
        self.word: str = word
        self.key: str | None = Core.dnsdumpster_key()
        if not self.key:
            raise MissingKey('dnsdumpster')
        self.total_results: list[dict] = []
        self.proxy: bool = False

    async def do_search(self) -> None:
        """
        Perform an asynchronous search for DNS information using the DNSDumpster API.
        """
        url = f'https://api.dnsdumpster.com/domain/{self.word}'  # Construct the API endpoint
        headers = {"X-API-Key": self.key}  # Define the necessary headers

        try:
            # Use AsyncFetcher to fetch data from the API
            responses = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)

            # Check if responses contain any data
            if not responses or len(responses) == 0:
                print('Error: No responses received from the DNSDumpster API')
                return

            # Extract the first response (note: fetch_all always returns a list)
            response = responses[0]

            # Validate the response and extract data
            if isinstance(response, dict) and response.get('status') == 200:
                self.total_results = response.get('a', [])  # Access the 'a' (hostnames) part of the response
            else:
                print(
                    f"Error: Received invalid response or status code: {response.get('status') if isinstance(response, dict) else 'Unknown'}")

        except Exception as e:
            print(f'An exception occurred in DNSDumpster: {e}')

    async def get_hostnames(self) -> list[str]:
        """
        Extract hostnames from the search results.
        """
        if not self.total_results:
            return []

        # Extract hostnames from DNS results
        return [entry.get('host', '') for entry in self.total_results if 'host' in entry]

    async def process(self, proxy: bool = False) -> None:
        """
        Start the search process.
        :param proxy: Enable or disable proxy usage.
        """
        self.proxy = proxy
        await self.do_search()
