from __future__ import annotations

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import (
    MAX_PROVIDER_JSON_BYTES,
    AsyncFetcher,
    Core,
    FetcherResponse,
    ProxyUnavailableError,
    ResponseStreamError,
)
from theHarvester.lib.hostnames import normalize_hostname, normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchJsmon:
    def __init__(self, word: str, limit: int | None) -> None:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError('JSMON limit must be a positive integer')
        self.word = normalize_hostname(word)
        self.limit = limit
        key = Core.jsmon_key()
        if not isinstance(key, str) or not key.strip():
            raise MissingKey('jsmon')
        self.key = key.strip()
        self.hostnames: set[str] = set()
        self.server = 'https://subdomains.jsmon.sh/api/domain/'

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        page = 1
        total_pages = None
        records_seen = 0
        try:
            async with AsyncFetcher.open_session(headers={'Api-Key': self.key}, proxy=proxy) as session:
                while True:
                    response = await AsyncFetcher.fetch(
                        session=session,
                        url=f'{self.server}{self.word}',
                        params={'page': page},
                        json=True,
                        include_metadata=True,
                        follow_redirects=False,
                        response_byte_limit=MAX_PROVIDER_JSON_BYTES,
                    )
                    if isinstance(response, FetcherResponse):
                        if response.status == 404 and page == 1:
                            return None
                        if response.status == 403:
                            return SourceExecutionReport('partial', 'quota-exhausted')
                    if error := provider_http_error(response):
                        return SourceExecutionReport(*error)
                    assert isinstance(response, FetcherResponse)
                    data = response.body
                    if not isinstance(data, dict) or not isinstance(data.get('subdomains'), list):
                        return SourceExecutionReport('failed', 'invalid-response')
                    pages = data.get('total_pages')
                    if (
                        type(data.get('page')) is not int
                        or data['page'] != page
                        or type(pages) is not int
                        or pages < 0
                        or (pages < page and not (page == 1 and pages == 0 and not data['subdomains']))
                        or (total_pages is not None and pages != total_pages)
                        or (not data['subdomains'] and page < pages)
                    ):
                        return SourceExecutionReport('failed', 'invalid-response')
                    total_pages = pages
                    remaining = self.limit - records_seen if self.limit is not None else len(data['subdomains'])
                    records = data['subdomains'][:remaining]
                    records_seen += len(records)
                    malformed = False
                    for value in records:
                        if not isinstance(value, str) or not value.strip():
                            malformed = True
                            continue
                        if hostname := normalize_scoped_hostname(value, self.word):
                            self.hostnames.add(hostname)
                    if malformed:
                        return SourceExecutionReport('failed', 'invalid-response')
                    if self.limit is not None and records_seen >= self.limit:
                        return SourceExecutionReport('completed', 'result-limit')
                    if page >= total_pages:
                        return None
                    page += 1
        except ProxyUnavailableError:
            return SourceExecutionReport('failed', 'proxy-unavailable')
        except ResponseStreamError as error:
            return SourceExecutionReport('partial', error.reason)
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')

    async def get_hostnames(self) -> set[str]:
        return self.hostnames
