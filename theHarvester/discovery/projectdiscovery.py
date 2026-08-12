import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse

logger = logging.getLogger(__name__)


class SearchDiscovery:
    """Collect subdomains from ProjectDiscovery's passive DNS dataset."""

    def __init__(self, word: str) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.proxy = False
        self.hostname = 'https://dns.projectdiscovery.io'
        self.key = self._get_api_key()
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _get_api_key(self) -> str:
        try:
            key = Core.projectdiscovery_key()
        except Exception as error:
            raise MissingKey('ProjectDiscovery') from error
        if not isinstance(key, str) or not key.strip():
            raise MissingKey('ProjectDiscovery')
        return key

    async def do_search(self) -> None:
        try:
            url = f'{self.hostname}/dns/{self.word}/subdomains'
            response = await AsyncFetcher.fetch_all(
                [url],
                headers={'User-Agent': Core.get_user_agent(), 'Authorization': self.key},
                proxy=self.proxy,
                json=True,
                include_metadata=True,
            )

            metadata = response[0] if response and isinstance(response[0], FetcherResponse) else None
            if metadata is None:
                self.execution_status = 'failed'
                self.stop_reason = 'transport-error'
                logger.info('No response from ProjectDiscovery for: %s', url)
                return
            if not 200 <= metadata.status < 300:
                self.execution_status = 'rate-limited' if metadata.status == 429 else 'failed'
                self.stop_reason = 'access-denied' if metadata.status in {401, 403} else f'http-{metadata.status}'
                logger.info('ProjectDiscovery request failed with HTTP %s', metadata.status)
                return

            try:
                data = metadata.body
                if not isinstance(data, (dict, list)):
                    self.execution_status = 'failed'
                    self.stop_reason = 'invalid-response'
                    logger.info('ProjectDiscovery returned malformed data')
                    return

                if isinstance(data, dict):
                    if 'error' in data:
                        error_message = data.get('message', data.get('error', 'Unknown error'))
                        self.execution_status = 'failed'
                        self.stop_reason = (
                            'access-denied' if 'unauthorized' in str(error_message).casefold() else 'provider-error'
                        )
                        logger.info('ProjectDiscovery returned an error')
                        return
                    subdomains = data.get('subdomains', []) or data.get('data', []) or data.get('results', [])
                else:
                    subdomains = data

                if not isinstance(subdomains, list):
                    self.execution_status = 'failed'
                    self.stop_reason = 'invalid-response'
                    logger.info('ProjectDiscovery returned malformed subdomain data')
                    return

                malformed_items = False
                for subdomain in subdomains:
                    if isinstance(subdomain, str):
                        label = subdomain
                    elif isinstance(subdomain, dict):
                        label = subdomain.get('subdomain', '') or subdomain.get('name', '')
                        if not isinstance(label, str) or not label:
                            malformed_items = True
                            logger.info('ProjectDiscovery ignored a malformed subdomain item')
                            continue
                    else:
                        malformed_items = True
                        logger.info('ProjectDiscovery ignored a malformed subdomain item')
                        continue
                    self.totalhosts.add(f'{label}.{self.word}'.lower() if label else self.word.lower())

                if malformed_items:
                    self.execution_status = 'partial' if self.totalhosts else 'failed'
                    self.stop_reason = 'invalid-response'
                else:
                    self.execution_status = 'completed'
                    self.stop_reason = None if subdomains else 'no-results'
            except Exception as error:
                self.execution_status = 'partial' if self.totalhosts else 'failed'
                self.stop_reason = 'invalid-response'
                logger.info('Failed to parse ProjectDiscovery response: %s', type(error).__name__)
        except MissingKey:
            raise
        except Exception as error:
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            logger.info('ProjectDiscovery API error: %s', type(error).__name__)

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
