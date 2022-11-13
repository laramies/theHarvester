from bs4 import BeautifulSoup
from theHarvester.lib.core import *


class SearchRapidDns:

    def __init__(self, word) -> None:
        self.word = word
        self.total_results: List = []
        self.proxy = False

    async def do_search(self):
        try:
            headers = {'User-agent': Core.get_user_agent()}
            # TODO see if it's worth adding sameip searches
            # f'{self.hostname}/sameip/{self.word}?full=1#result'
            urls = [f'https://rapiddns.io/subdomain/{self.word}?full=1#result']
            responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
            if len(responses[0]) <= 1:
                return self.total_results
            soup = BeautifulSoup(responses[0], 'html.parser')
            rows = soup.find("table").find("tbody").find_all("tr")
            if rows:
                # Validation check
                for row in rows:
                    cells = row.find_all("td")
                    if len(cells) >= 0:
                        # sanity check
                        subdomain = str(cells[0].get_text())
                        if cells[-1].get_text() == 'CNAME':
                            self.total_results.append(f'{subdomain}')
                        else:
                            self.total_results.append(f'{subdomain}:{str(cells[1].get_text()).strip()}')
                self.total_results = list({domain for domain in self.total_results})
        except Exception as e:
            print(f'An exception has occurred: {str(e)}')

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_hostnames(self):
        return self.total_results
