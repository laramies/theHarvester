from theHarvester.lib.core import AsyncFetcher


class SearchCertspoter:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.proxy = False

    async def do_search(self) -> None:
        base_url = f'https://api.certspotter.com/v1/issuances?domain={self.word}&expand=dns_names'
        try:
            response = await AsyncFetcher.fetch_all([base_url], json=True, proxy=self.proxy)
            response = response[0]
            if isinstance(response, list):
                for dct in response:
                    for key, value in dct.items():
                        if key == 'dns_names':
                            self.totalhosts.update({name for name in value if isinstance(name, str) and name})
            elif isinstance(response, dict):
                dns_names = response.get('dns_names')
                if isinstance(dns_names, list):
                    self.totalhosts.update({name for name in dns_names if isinstance(name, str) and name})
                elif isinstance(dns_names, str) and dns_names:
                    self.totalhosts.add(dns_names)
            else:
                self.totalhosts.update({''})
        except IndexError:
            print('No data returned from Cert Spotter.')
        except ConnectionError:
            print('Network connection failed.')
        except Exception as e:
            print(f'Unexpected error occurred: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
        print('\tSearching results.')
