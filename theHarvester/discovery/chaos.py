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
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

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
                self.execution_status = 'failed'
                self.stop_reason = 'transport-error'
                logger.info(f'No response from Chaos API for: {url}')
                return
            if not 200 <= metadata.status < 300:
                self.execution_status = 'rate-limited' if metadata.status == 429 else 'failed'
                self.stop_reason = 'access-denied' if metadata.status in {401, 403} else f'http-{metadata.status}'
                logger.info(f'Chaos request failed with HTTP {metadata.status}')
                return

            try:
                data = metadata.body
                if not isinstance(data, (dict, list)):
                    self.execution_status = 'failed'
                    self.stop_reason = 'invalid-response'
                    logger.info('Chaos returned malformed data')
                    return

                if isinstance(data, dict):
                    # Check for error messages
                    if 'error' in data:
                        error_msg = data.get('message', data.get('error', 'Unknown error'))
                        logger.info('Chaos API returned an error')
                        self.execution_status = 'failed'
                        self.stop_reason = 'access-denied' if 'unauthorized' in str(error_msg).casefold() else 'provider-error'
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
                    self.execution_status = 'failed'
                    self.stop_reason = 'invalid-response'
                    logger.info('Chaos returned malformed subdomain data')
                    return
                malformed_items = False
                for subdomain in subdomains:
                    if isinstance(subdomain, str):
                        label = subdomain
                    elif isinstance(subdomain, dict):
                        label = subdomain.get('subdomain', '') or subdomain.get('name', '')
                        if not isinstance(label, str) or not label:
                            malformed_items = True
                            logger.info('Chaos ignored a malformed subdomain item')
                            continue
                    else:
                        malformed_items = True
                        logger.info('Chaos ignored a malformed subdomain item')
                        continue
                    full_domain = f'{label}.{self.word}' if label else self.word
                    self.totalhosts.add(full_domain.lower())
                if malformed_items:
                    self.execution_status = 'partial' if self.totalhosts else 'failed'
                    self.stop_reason = 'invalid-response'
                else:
                    self.execution_status = 'completed'
                    self.stop_reason = None if subdomains else 'no-results'

            except Exception as error:
                self.execution_status = 'partial' if self.totalhosts else 'failed'
                self.stop_reason = 'invalid-response'
                logger.info('Failed to parse Chaos response: %s', type(error).__name__)

        except MissingKey:
            raise
        except Exception as error:
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            logger.info('Chaos API error: %s', type(error).__name__)

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
