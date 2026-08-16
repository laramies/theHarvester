import logging
from ipaddress import ip_address

#!/usr/bin/env python3
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchDNSDumpster:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.dnsdumpster_key()
        if not self.key:
            raise MissingKey('DNSDumpster')
        self.hosts: set = set()
        self.ips: set = set()
        self.base_url = 'https://api.dnsdumpster.com'
        self.proxy = False

    async def do_search(self) -> SourceExecutionReport | None:
        url = f'{self.base_url}/domain/{self.word}'
        headers = {'User-Agent': Core.get_user_agent(), 'X-API-Key': self.key}
        try:
            response = await AsyncFetcher.fetch_all(
                [url],
                headers=headers,
                json=True,
                proxy=self.proxy,
                include_metadata=True,
            )
        except Exception as error:
            logger.info('DNSDumpster request failed: %s', type(error).__name__)
            return SourceExecutionReport('failed', 'transport-error')

        metadata = response[0] if response and isinstance(response[0], FetcherResponse) else None
        if metadata is None:
            return SourceExecutionReport('failed', 'transport-error')
        if metadata.status == 429:
            return SourceExecutionReport('rate-limited', 'http-429')
        if metadata.status in {401, 403}:
            return SourceExecutionReport('failed', 'access-denied')
        if not 200 <= metadata.status < 300:
            return SourceExecutionReport('failed', f'http-{metadata.status}')
        if not isinstance(metadata.body, dict):
            return SourceExecutionReport('failed', 'invalid-response')
        if 'error' in metadata.body:
            return SourceExecutionReport('failed', 'provider-error')
        if not any(record_type in metadata.body for record_type in ('a', 'cname', 'mx', 'ns', 'txt')):
            return SourceExecutionReport('failed', 'invalid-response')

        malformed = False
        records = []
        for record_type in ('a', 'ns'):
            group = metadata.body.get(record_type, [])
            if not isinstance(group, list):
                malformed = True
                continue
            records.extend(group)

        for record in records:
            if not isinstance(record, dict):
                malformed = True
                continue
            raw_host = record.get('host')
            if not isinstance(raw_host, str) or not raw_host.strip():
                malformed = True
                continue
            host = normalize_scoped_hostname(raw_host, self.word)
            if host is None:
                continue
            self.hosts.add(host)
            ip_records = record.get('ips', [])
            if not isinstance(ip_records, list):
                malformed = True
                continue
            for ip_info in ip_records:
                if not isinstance(ip_info, dict):
                    malformed = True
                    continue
                candidate = ip_info.get('ip')
                if not isinstance(candidate, str):
                    malformed = True
                    continue
                try:
                    self.ips.add(str(ip_address(candidate)))
                except (TypeError, ValueError):
                    malformed = True

        if malformed:
            return SourceExecutionReport('failed', 'invalid-response')
        return None

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()

    async def get_hostnames(self) -> set:
        return self.hosts

    async def get_ips(self) -> set:
        return self.ips
