import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchHibpVerified:
    def __init__(self, word: str) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.api_key = (Core.hibpverified_key() or '').strip()
        if not self.api_key:
            raise MissingKey('HIBP verified domain')
        self.base_url = 'https://haveibeenpwned.com/api/v3'
        self.headers = {'hibp-api-key': self.api_key, 'User-Agent': Core.get_user_agent()}
        self.emails: set[str] = set()
        self.breach_names: set[str] = set()

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        try:
            responses = await AsyncFetcher.fetch_all(
                [f'{self.base_url}/breachedDomain/{self.word}'],
                headers=self.headers,
                json=True,
                proxy=proxy,
                include_metadata=True,
            )
        except OSError, RuntimeError, ValueError:
            logger.info('HIBP verified-domain request failed')
            return SourceExecutionReport('failed', 'transport-error')

        response = responses[0] if responses and isinstance(responses[0], FetcherResponse) else None
        if response is None:
            logger.info('HIBP verified-domain request failed')
            return SourceExecutionReport('failed', 'transport-error')
        if response.status == 403:
            logger.info('HIBP verified-domain target is not verified for this API key (HTTP 403)')
            return SourceExecutionReport('failed', 'access-denied')
        if response.status == 404:
            return None
        if failure := provider_http_error(response):
            if response.status == 429:
                logger.info('HIBP verified-domain request was rate limited (HTTP 429)')
            else:
                logger.info(f'HIBP verified-domain request failed with HTTP {response.status}')
            return SourceExecutionReport(*failure)
        if response.status != 200:
            logger.info(f'HIBP verified-domain request failed with HTTP {response.status}')
            return SourceExecutionReport('failed', f'http-{response.status}')
        if not isinstance(response.body, dict):
            logger.info('HIBP verified-domain returned malformed account data')
            return SourceExecutionReport('failed', 'invalid-response')
        malformed = False
        for alias, breaches in response.body.items():
            if not (
                isinstance(alias, str)
                and alias.strip()
                and '@' not in alias
                and not any(character.isspace() for character in alias)
                and isinstance(breaches, list)
                and all(isinstance(breach, str) and breach.strip() for breach in breaches)
            ):
                malformed = True
                continue
            self.emails.add(f'{alias.strip()}@{self.word}')
            self.breach_names.update(breach.strip() for breach in breaches)
        if malformed:
            logger.info('HIBP verified-domain returned malformed account data')
            return SourceExecutionReport('failed', 'invalid-response')
        return None

    async def get_emails(self) -> set[str]:
        return self.emails

    async def get_breach_names(self) -> set[str]:
        return self.breach_names
