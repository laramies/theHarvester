from __future__ import annotations

import json
import logging
from urllib.parse import quote

import aiohttp

from theHarvester import __version__
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.lib.run import SourceFinding, SourceIncompleteError, SourceRateLimitedError

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

    def _partial_findings(self) -> tuple[SourceFinding, ...]:
        return tuple(SourceFinding(hostname) for hostname in sorted(self.totalhosts))

    async def do_search(self) -> None:
        query = quote(f'*.{self.target_domain}', safe='*.')
        url = f'{self.BASE_URL}/{query}?limit=0'
        headers = {
            'Accept': 'application/x-ndjson',
            'User-Agent': f'theHarvester/{__version__}',
            'X-API-Key': self.key,
        }
        timeout = aiohttp.ClientTimeout(total=120)
        proxy_url, proxy_type = AsyncFetcher._resolve_proxy(self.proxy)

        async with await AsyncFetcher._build_session(headers, timeout, proxy_url, proxy_type) as session:
            async with session.get(url, proxy=proxy_url if proxy_type == 'http' else None) as response:
                if response.status == 429:
                    raise SourceRateLimitedError('DNSDB rate limit reached')
                if response.status in {401, 403}:
                    raise PermissionError('DNSDB authentication failed')
                if response.status == 503:
                    raise ConnectionError('DNSDB concurrent connection limit exceeded')
                if response.status != 200:
                    raise ConnectionError(f'DNSDB returned HTTP {response.status}')

                first_record = True
                async for line in response.content:
                    try:
                        record = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        message = 'DNSDB returned malformed NDJSON; partial results were preserved.'
                        logger.info(message)
                        raise SourceIncompleteError(message, findings=self._partial_findings())
                    if not isinstance(record, dict):
                        message = 'DNSDB returned an invalid stream record; partial results were preserved.'
                        logger.info(message)
                        raise SourceIncompleteError(message, findings=self._partial_findings())
                    if first_record:
                        first_record = False
                        if record.get('cond') != 'begin':
                            message = 'DNSDB stream did not begin correctly; no results were accepted.'
                            logger.info(message)
                            raise SourceIncompleteError(message)
                        continue

                    condition = record.get('cond')
                    if condition in {'succeeded', 'limited', 'failed'}:
                        if condition == 'limited':
                            message = 'DNSDB stream ended with limited; partial results were preserved.'
                            logger.info(message)
                            raise SourceRateLimitedError(message, findings=self._partial_findings())
                        if condition == 'failed':
                            message = 'DNSDB stream ended with failed; partial results were preserved.'
                            logger.info(message)
                            raise SourceIncompleteError(message, findings=self._partial_findings())
                        return
                    obj = record.get('obj')
                    if not isinstance(obj, dict) or not isinstance(obj.get('rrname'), str):
                        message = 'DNSDB returned an invalid stream record; partial results were preserved.'
                        logger.info(message)
                        raise SourceIncompleteError(message, findings=self._partial_findings())
                    if hostname := self._hostname(obj['rrname']):
                        self.totalhosts.add(hostname)

                message = 'DNSDB stream ended without a terminal condition; partial results were preserved.'
                logger.info(message)
                raise SourceIncompleteError(message, findings=self._partial_findings())

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool | str = False) -> None:
        self.proxy = proxy
        try:
            await self.do_search()
        except (aiohttp.ClientError, TimeoutError) as error:
            message = f'DNSDB request failed with {type(error).__name__}; partial results were preserved.'
            logger.info(message)
            raise SourceIncompleteError(message, findings=self._partial_findings()) from error
