import logging

from theHarvester.lib.core import AsyncFetcher, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname

logger = logging.getLogger(__name__)


class SearchShodanCt:
    """Collect hostname evidence from Shodan's public CT mirror.

    API documentation: https://ctl.shodan.io/
    """

    def __init__(self, word: str) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.hostnames: set[str] = set()
        self.proxy = False

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        try:
            responses: list[FetcherResponse | None] = await AsyncFetcher.fetch_all(
                [f'https://ctl.shodan.io/api/v1/domain/{self.word}/hostnames'],
                json=True,
                proxy=self.proxy,
                include_metadata=True,
            )
        except Exception as error:
            logger.info(f'Shodan CT request failed: {error}')
            return

        response = responses[0] if responses else None
        if response is None:
            logger.info('Shodan CT request failed')
            return
        if not 200 <= response.status < 300:
            logger.info(f'Shodan CT request failed with HTTP {response.status}')
            return
        if not isinstance(response.body, list):
            logger.info('Shodan CT returned malformed data')
            return

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

    async def get_hostnames(self) -> set[str]:
        return self.hostnames
