from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from spyse import Client, SearchQuery, QueryParam, DomainSearchParams, Operators


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
        self.client = Client(self.key)

    async def do_search(self):
        fetch_count = 0

        query = SearchQuery()
        query.append_param(QueryParam(DomainSearchParams.name, Operators.ends_with, self.word))

        try:
            total = self.client.count_domains(query)
            if total == 0:
                return

            # The default "Search" method returns only first 10 000 subdomains
            # To obtain more than 10 000 subdomains the "Scroll" method should be using
            # Note: The "Scroll" method is only available for "PRO" customers, so we need to check
            # self.client.account.is_scroll_search_enabled param
            if total > self.client.SEARCH_RESULTS_LIMIT and self.client.account.is_scroll_search_enabled:
                scroll_id = None
                while True:
                    scroll_results = self.client.scroll_domains(query, scroll_id)

                    scroll_id = scroll_results.search_id
                    for domain in scroll_results.results:
                        self.hosts.add(domain.name)

                    fetch_count += len(scroll_results.results)

                    if len(scroll_results.results) == 0 or fetch_count >= self.limit:
                        break
            else:
                # Spyse allows to get up to 100 results per one request
                max_limit = 100
                # Spyse "search" methods allows to fetch up to 10 000 first results
                max_offset = 9900
                offset = 0

                while True:
                    limit = max_limit if self.limit - fetch_count > max_limit else self.limit - fetch_count
                    if limit <= 0:
                        break

                    results = self.client.search_domains(query, limit, offset)

                    if len(results.results) == 0:
                        break

                    for domain in results.results:
                        self.hosts.add(domain.name)

                    offset += max_limit
                    fetch_count += len(results.results)
                    if offset > max_offset or fetch_count == total:
                        break

        except Exception as e:
            print(f'An exception has occurred: {e}')

    async def get_hostnames(self):
        return self.hosts

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()
