import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse

logger = logging.getLogger(__name__)


class SearchChaos:
    """Class uses ProjectDiscovery Chaos subdomain enumeration API"""

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.proxy = False
        self.hostname = 'https://dns.projectdiscovery.io'
        self.key = self._get_api_key()

    def _get_api_key(self) -> str:
        """Get Chaos API key"""
        try:
            key = Core.projectdiscovery_key()
        except Exception as error:
            raise MissingKey('Chaos (ProjectDiscovery)') from error
        if not isinstance(key, str) or not key.strip():
            raise MissingKey('Chaos (ProjectDiscovery)')
        return key

    async def do_search(self) -> None:
        try:
            headers = {'User-agent': Core.get_user_agent(), 'Authorization': f'Bearer {self.key}'}

            # Chaos API endpoint for subdomain enumeration
            url = f'{self.hostname}/dns/{self.word}/subdomains'

            response = await AsyncFetcher.fetch_all(
                [url],
                headers=headers,
                proxy=self.proxy,
                json=True,
                include_metadata=True,
            )

            metadata = response[0] if response and isinstance(response[0], FetcherResponse) else None
            if metadata is None:
                logger.info(f'No response from Chaos API for: {url}')
                return
            if not 200 <= metadata.status < 300:
                logger.info(f'Chaos request failed with HTTP {metadata.status}')
                return

            try:
                data = metadata.body
                if not isinstance(data, (dict, list)):
                    logger.info('Chaos returned malformed data')
                    return

                if isinstance(data, dict):
                    # Check for error messages
                    if 'error' in data:
                        error_msg = data.get('message', data.get('error', 'Unknown error'))
                        logger.info('Chaos API returned an error')
                        if 'unauthorized' in str(error_msg).lower():
                            raise MissingKey('Chaos (ProjectDiscovery)')
                        return

                    # Extract subdomains from response
                    subdomains = data.get('subdomains', [])
                    if not subdomains:
                        subdomains = data.get('data', [])
                    if not subdomains:
                        subdomains = data.get('results', [])

                else:
                    subdomains = data

                if not isinstance(subdomains, list):
                    logger.info('Chaos returned malformed subdomain data')
                    return
                for subdomain in subdomains:
                    if isinstance(subdomain, str):
                        label = subdomain
                    elif isinstance(subdomain, dict):
                        label = subdomain.get('subdomain', '') or subdomain.get('name', '')
                        if not isinstance(label, str) or not label:
                            logger.info('Chaos ignored a malformed subdomain item')
                            continue
                    else:
                        logger.info('Chaos ignored a malformed subdomain item')
                        continue
                    full_domain = f'{label}.{self.word}' if label else self.word
                    self.totalhosts.add(full_domain.lower())

            except Exception as e:
                logger.info(f'Failed to parse Chaos response: {e}')

        except MissingKey:
            raise
        except Exception as e:
            logger.info(f'Chaos API error: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
