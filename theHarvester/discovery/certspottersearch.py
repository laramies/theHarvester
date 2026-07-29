import logging
from urllib.parse import urlencode

from theHarvester.lib.core import AsyncFetcher

logger = logging.getLogger(__name__)


class SearchCertspoter:
    """Search the SSLMate Cert Spotter CT Search API.

    API reference: https://sslmate.com/help/reference/ct_search_api_v1
    """

    def __init__(self, word) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.totalhosts: set = set()
        self.proxy = False

    async def do_search(self) -> None:
        base_url = 'https://api.certspotter.com/v1/issuances'
        cursor = None
        seen_cursors: set[str] = set()
        try:
            while True:
                params = {
                    'domain': self.word,
                    'include_subdomains': 'true',
                    'expand': 'dns_names',
                }
                if cursor is not None:
                    params['after'] = cursor

                responses = await AsyncFetcher.fetch_all([f'{base_url}?{urlencode(params)}'], json=True, proxy=self.proxy)
                if not responses:
                    logger.warning('Cert Spotter stopped early; results may be incomplete.')
                    break

                page = responses[0]
                if isinstance(page, dict):
                    code = page.get('code')
                    if isinstance(code, str):
                        logger.warning(f'Cert Spotter stopped early ({code}); results may be incomplete.')
                    else:
                        logger.warning('Cert Spotter stopped early; results may be incomplete.')
                    break
                if not isinstance(page, list):
                    logger.warning('Cert Spotter stopped early; results may be incomplete.')
                    break
                if not page:
                    break

                malformed_issuance = False
                for issuance in page:
                    if not isinstance(issuance, dict):
                        malformed_issuance = True
                        continue
                    dns_names = issuance.get('dns_names')
                    if not isinstance(dns_names, list):
                        malformed_issuance = True
                        continue
                    for name in dns_names:
                        if not isinstance(name, str):
                            malformed_issuance = True
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
                if malformed_issuance:
                    logger.warning('Cert Spotter ignored malformed issuance data; results may be incomplete.')

                last_issuance = page[-1]
                next_cursor = last_issuance.get('id') if isinstance(last_issuance, dict) else None
                if isinstance(next_cursor, str):
                    next_cursor = next_cursor.strip()
                if not isinstance(next_cursor, str) or not next_cursor:
                    logger.warning(
                        'Cert Spotter stopped early because the response did not provide a valid cursor; '
                        'results may be incomplete.'
                    )
                    break
                if next_cursor in seen_cursors:
                    logger.warning(
                        'Cert Spotter stopped early because the response repeated a cursor; results may be incomplete.'
                    )
                    break
                seen_cursors.add(next_cursor)
                cursor = next_cursor
        except ConnectionError:
            logger.warning('Cert Spotter network connection failed; results may be incomplete.')
        except Exception:
            logger.warning('Cert Spotter stopped after an unexpected error; results may be incomplete.')

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
        logger.info('\tSearching results.')
