import logging
from urllib.parse import urlencode

from theHarvester.lib.core import AsyncFetcher

logger = logging.getLogger(__name__)


class SearchCertspoter:
    MAX_PAGES = 10

    def __init__(self, word) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.totalhosts: set = set()
        self.proxy = False

    async def do_search(self) -> None:
        base_url = 'https://api.certspotter.com/v1/issuances'
        cursor = None
        seen_cursors: set[str] = set()
        try:
            for _ in range(self.MAX_PAGES):
                params = {
                    'domain': self.word,
                    'include_subdomains': 'true',
                    'expand': 'dns_names',
                }
                if cursor is not None:
                    params['after'] = cursor

                responses = await AsyncFetcher.fetch_all([f'{base_url}?{urlencode(params)}'], json=True, proxy=self.proxy)
                if not responses:
                    break

                page = responses[0]
                if isinstance(page, dict):
                    code = page.get('code')
                    if isinstance(code, str):
                        logger.warning(f'Cert Spotter stopped early ({code}); results may be incomplete.')
                    break
                if not isinstance(page, list):
                    logger.warning('Cert Spotter stopped early; results may be incomplete.')
                    break
                if not page:
                    break

                for issuance in page:
                    if not isinstance(issuance, dict):
                        continue
                    dns_names = issuance.get('dns_names')
                    if isinstance(dns_names, list):
                        for name in dns_names:
                            if not isinstance(name, str):
                                continue
                            name = name.strip().lower().rstrip('.').removeprefix('*.')
                            labels = name.split('.')
                            if (
                                name
                                and len(name) <= 253
                                and name.isascii()
                                and '*' not in name
                                and not any(character.isspace() for character in name)
                                and all(
                                    label
                                    and len(label) <= 63
                                    and label[0].isalnum()
                                    and label[-1].isalnum()
                                    and all(character.isalnum() or character == '-' for character in label)
                                    for label in labels
                                )
                                and (name == self.word or name.endswith(f'.{self.word}'))
                            ):
                                self.totalhosts.add(name)

                last_issuance = page[-1]
                next_cursor = last_issuance.get('id') if isinstance(last_issuance, dict) else None
                if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                    break
                seen_cursors.add(next_cursor)
                cursor = next_cursor
            else:
                logger.warning(f'Cert Spotter stopped after {self.MAX_PAGES} pages; results may be incomplete.')
        except ConnectionError:
            logger.info('Network connection failed.')
        except Exception as e:
            logger.info(f'Unexpected error occurred: {e}')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
        logger.info('\tSearching results.')
