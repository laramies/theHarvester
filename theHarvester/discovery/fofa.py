import base64
import logging
from ipaddress import ip_address
from urllib.parse import urlparse

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname

logger = logging.getLogger(__name__)


class SearchFofa:
    """Class uses Fofa API to search for domain and host intelligence
    Fofa is a Chinese search engine for network-connected devices
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False
        self.hostname = 'https://fofa.info'
        self.api_key, self.email = self._get_api_credentials()

    def _get_api_credentials(self) -> tuple[str, str]:
        """Get Fofa API credentials"""
        try:
            api_key, email = Core.fofa_key()
        except Exception as error:
            raise MissingKey('Fofa API (key and email required)') from error
        if not all(isinstance(value, str) and value.strip() for value in (api_key, email)):
            raise MissingKey('Fofa API (key and email required)')
        return api_key, email

    async def do_search(self) -> None:
        try:
            headers = {'User-agent': Core.get_user_agent()}

            # Fofa search query - encode in base64
            query = f'domain="{self.word}"'
            query_encoded = base64.b64encode(query.encode()).decode()

            # Fofa API endpoint
            url = f'{self.hostname}/api/v1/search/all'
            params = {
                'email': self.email,
                'key': self.api_key,
                'qbase64': query_encoded,
                'fields': 'host,ip,port,protocol,title',
                'size': 100,  # Limit results
            }

            # Build URL with parameters
            param_string = '&'.join([f'{k}={v}' for k, v in params.items()])
            full_url = f'{url}?{param_string}'

            response = await AsyncFetcher.fetch_all(
                [full_url],
                headers=headers,
                proxy=self.proxy,
                json=True,
                include_metadata=True,
            )

            metadata = response[0] if response and isinstance(response[0], FetcherResponse) else None
            if metadata is None:
                logger.info(f'No response from Fofa API for: {self.word}')
                return
            if not 200 <= metadata.status < 300:
                logger.info(f'Fofa request failed with HTTP {metadata.status}')
                return

            try:
                data = metadata.body
                if not isinstance(data, dict):
                    logger.info('Fofa returned malformed data')
                    return

                # Check for errors
                if data.get('error', False):
                    logger.info('Fofa API returned an error')
                    return

                # Extract results
                results = data.get('results', [])
                if not isinstance(results, list):
                    logger.info('Fofa returned malformed results')
                    return
                for result in results:
                    if isinstance(result, list) and len(result) >= 2:
                        host = result[0]  # host field
                        ip = result[1]  # ip field

                        # Add host if it's related to our domain
                        if isinstance(host, str):
                            parsed = urlparse(host if '://' in host else f'//{host}')
                            if clean_host := normalize_scoped_hostname(parsed.hostname, self.word):
                                self.totalhosts.add(clean_host)

                        # Add IP
                        if isinstance(ip, str) and ip:
                            try:
                                self.totalips.add(str(ip_address(ip)))
                            except ValueError:
                                continue

            except Exception as e:
                logger.info(f'Failed to parse Fofa response: {e}')

        except MissingKey:
            raise
        except Exception as e:
            logger.info(f'Fofa API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
