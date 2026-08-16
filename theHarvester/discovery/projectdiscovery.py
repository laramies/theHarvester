import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport, SourceReportStatus

logger = logging.getLogger(__name__)


class SearchDiscovery:
    """Collect subdomains from ProjectDiscovery's passive DNS dataset."""

    def __init__(self, word: str) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.proxy = False
        self.hostname = 'https://dns.projectdiscovery.io'
        self.key = self._get_api_key()

    def _get_api_key(self) -> str:
        try:
            key = Core.projectdiscovery_key()
        except Exception as error:
            raise MissingKey('ProjectDiscovery') from error
        if not isinstance(key, str) or not key.strip():
            raise MissingKey('ProjectDiscovery')
        return key

    async def do_search(self) -> SourceExecutionReport | None:
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
                logger.info('No response from ProjectDiscovery for: %s', url)
                return SourceExecutionReport('failed', 'transport-error')
            if not 200 <= metadata.status < 300:
                logger.info('ProjectDiscovery request failed with HTTP %s', metadata.status)
                status: SourceReportStatus = 'rate-limited' if metadata.status == 429 else 'failed'
                reason = 'access-denied' if metadata.status in {401, 403} else f'http-{metadata.status}'
                return SourceExecutionReport(status, reason)

            try:
                data = metadata.body
                if not isinstance(data, (dict, list)):
                    logger.info('ProjectDiscovery returned malformed data')
                    return SourceExecutionReport('failed', 'invalid-response')

                if isinstance(data, dict):
                    if 'error' in data:
                        error_message = data.get('message', data.get('error', 'Unknown error'))
                        reason = 'access-denied' if 'unauthorized' in str(error_message).casefold() else 'provider-error'
                        logger.info('ProjectDiscovery returned an error')
                        return SourceExecutionReport('failed', reason)
                    subdomains = data.get('subdomains', []) or data.get('data', []) or data.get('results', [])
                else:
                    subdomains = data

                if not isinstance(subdomains, list):
                    logger.info('ProjectDiscovery returned malformed subdomain data')
                    return SourceExecutionReport('failed', 'invalid-response')

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
                    return SourceExecutionReport('failed', 'invalid-response')
                return None
            except Exception as error:
                logger.info('Failed to parse ProjectDiscovery response: %s', type(error).__name__)
                return SourceExecutionReport('failed', 'invalid-response')
        except MissingKey:
            raise
        except Exception as error:
            logger.info('ProjectDiscovery API error: %s', type(error).__name__)
            return SourceExecutionReport('failed', 'transport-error')

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
