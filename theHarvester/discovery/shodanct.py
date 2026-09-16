import logging

from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchShodanCt:
    """Collect hostname evidence from Shodan's public CT mirror.

    API documentation: https://ctl.shodan.io/
    """

    def __init__(self, word: str) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.hostnames: set[str] = set()
        self.proxy = False

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            responses: list[FetcherResponse | None] = await AsyncFetcher.fetch_all(
                [f'https://ctl.shodan.io/api/v1/domain/{self.word}/hostnames'],
                json=True,
                proxy=self.proxy,
                include_metadata=True,
            )
        except Exception as error:
            logger.info(f'Shodan CT request failed: {type(error).__name__}')
            return SourceExecutionReport('failed', 'transport-error')

        response = responses[0] if responses else None
        if response is None:
            logger.info('Shodan CT request failed')
            return SourceExecutionReport('failed', 'transport-error')
        if failure := provider_http_error(response):
            logger.info(f'Shodan CT request failed with HTTP {response.status}')
            return SourceExecutionReport(*failure)
        if not isinstance(response.body, list):
            logger.info('Shodan CT returned malformed data')
            return SourceExecutionReport('failed', 'invalid-response')

        malformed = False
        for candidate in response.body:
            if not isinstance(candidate, str):
                malformed = True
                continue
            normalized = normalize_scoped_hostname(candidate.strip().removeprefix('*.'), self.word)
            if normalized is None:
                continue
            labels = normalized.split('.')
            if (
                len(normalized) > 253
                or not normalized.isascii()
                or any(
                    not label
                    or len(label) > 63
                    or not label[0].isalnum()
                    or not label[-1].isalnum()
                    or not all(character.isalnum() or character == '-' for character in label)
                    for label in labels
                )
            ):
                malformed = True
                continue
            self.hostnames.add(normalized)

        if malformed:
            logger.info('Shodan CT ignored malformed hostname data')
            return SourceExecutionReport('failed', 'invalid-response')
        return None

    async def get_hostnames(self) -> set[str]:
        return self.hostnames
