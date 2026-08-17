from __future__ import annotations

import json
import logging
from urllib.parse import quote

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchDNSDB:
    """Collect RRset owner names from the DNSDB v2 streaming API.

    API docs: https://docs.domaintools.com/api/dnsdb/lookups/rrset-lookups/
    Streaming protocol: https://docs.domaintools.com/api/dnsdb/streaming-protocol/
    """

    BASE_URL = 'https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name'

    def __init__(self, target_domain: str) -> None:
        self.target_domain = target_domain.strip().lower().rstrip('.').encode('idna').decode('ascii')
        key = Core.dnsdb_key()
        if not isinstance(key, str) or not key.strip():
            raise MissingKey('dnsdb')
        self.key = key
        self.totalhosts: set[str] = set()
        self.proxy: bool | str = False

    def _hostname(self, value: object) -> str | None:
        if not isinstance(value, str):
            return None
        value = value.strip().rstrip('.')
        if value.startswith('_WILDCARD_.') or '*' in value or any(character.isspace() for character in value):
            return None
        try:
            hostname = value.lower().encode('idna').decode('ascii')
        except UnicodeError:
            return None
        if hostname != self.target_domain and hostname.endswith(f'.{self.target_domain}'):
            return hostname
        return None

    async def do_search(self) -> SourceExecutionReport | None:
        query = quote(f'*.{self.target_domain}', safe='*.')
        url = f'{self.BASE_URL}/{query}?limit=0'
        headers = {
            'Accept': 'application/x-ndjson',
            'User-Agent': Core.get_user_agent(),
            'X-API-Key': self.key,
        }
        async with AsyncFetcher.stream_records(
            url,
            framing='ndjson',
            headers=headers,
            proxy=self.proxy,
            # Never forward the provider credential to a redirect target.
            follow_redirects=False,
            request_timeout=120,
        ) as response:
            if failure := provider_http_error(FetcherResponse(None, response.status, response.headers)):
                return SourceExecutionReport(*failure)

            first_record = True
            async for line in response:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError, RecursionError:
                    logger.info('DNSDB returned malformed NDJSON; partial results were preserved.')
                    return SourceExecutionReport('failed', 'invalid-response')
                if not isinstance(record, dict):
                    logger.info('DNSDB returned an invalid stream record; partial results were preserved.')
                    return SourceExecutionReport('failed', 'invalid-response')
                if first_record:
                    first_record = False
                    if record.get('cond') != 'begin':
                        logger.info('DNSDB stream did not begin correctly; no results were accepted.')
                        return SourceExecutionReport('failed', 'invalid-response')
                    continue

                condition = record.get('cond')
                if condition in {'succeeded', 'limited', 'failed'}:
                    if condition != 'succeeded':
                        logger.info(f'DNSDB stream ended with {condition}; partial results were preserved.')
                    if condition == 'limited':
                        return SourceExecutionReport('rate-limited', 'provider-limited')
                    if condition == 'failed':
                        return SourceExecutionReport('failed', 'provider-failed')
                    return None
                if condition is not None:
                    return SourceExecutionReport('failed', 'invalid-response')
                obj = record.get('obj')
                if not isinstance(obj, dict):
                    return SourceExecutionReport('failed', 'invalid-response')
                rrname = obj.get('rrname')
                if not isinstance(rrname, str) or not rrname.strip():
                    return SourceExecutionReport('failed', 'invalid-response')
                if hostname := self._hostname(rrname):
                    self.totalhosts.add(hostname)

            logger.info('DNSDB stream ended without a terminal condition; partial results were preserved.')
            return SourceExecutionReport('failed', 'invalid-response')

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool | str = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()
        except ResponseStreamError as error:
            logger.info(f'DNSDB request failed with {type(error).__name__}; partial results were preserved.')
            return SourceExecutionReport('failed', error.reason)
