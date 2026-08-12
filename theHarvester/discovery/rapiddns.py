import ipaddress
import logging

from bs4 import BeautifulSoup
from bs4.element import Tag

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse

logger = logging.getLogger(__name__)


class SearchRapidDns:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.totalips: set[str] = set()
        self.host_ip_pairs: set[tuple[str, str]] = set()
        self.proxy = False

    async def do_search(self):
        try:
            headers = {'User-Agent': Core.get_browser_user_agent()}
            # TODO see if it's worth adding sameip searches
            # f'{self.hostname}/sameip/{self.word}?full=1#result'
            urls = [f'https://rapiddns.io/subdomain/{self.word}?full=1#result']
            responses: list[FetcherResponse | None] = await AsyncFetcher.fetch_all(
                urls,
                headers=headers,
                proxy=self.proxy,
                include_metadata=True,
            )
            response = responses[0] if responses else None
            if response is None:
                logger.info('RapidDNS request failed')
                return
            if not 200 <= response.status < 300:
                logger.info(f'RapidDNS request failed with HTTP {response.status}')
                return
            if not isinstance(response.body, str) or len(response.body) <= 1:
                return
            soup = BeautifulSoup(response.body, 'html.parser')
            table_el = soup.find('table')
            if not isinstance(table_el, Tag):
                return
            tbody_el = table_el.find('tbody')
            if not isinstance(tbody_el, Tag):
                return
            rows = tbody_el.find_all('tr')
            if rows:
                # Validation check
                for row in rows:
                    if not isinstance(row, Tag):
                        continue
                    cells = row.find_all('td')
                    if len(cells) < 2:
                        continue
                    subdomain = cells[0].get_text(strip=True)
                    if not subdomain:
                        continue
                    self.totalhosts.add(subdomain)
                    if cells[-1].get_text(strip=True).upper() not in {'A', 'AAAA'}:
                        continue
                    try:
                        address = str(ipaddress.ip_address(cells[1].get_text(strip=True)))
                    except ValueError:
                        continue
                    self.totalips.add(address)
                    self.host_ip_pairs.add((subdomain, address))
        except Exception as e:
            logger.info(f'RapidDNS error: {e!s}')

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_hostnames(self) -> list[str]:
        return list(self.totalhosts)

    async def get_ips(self) -> set[str]:
        return self.totalips

    async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
        return self.host_ip_pairs
