from __future__ import annotations

from typing import Any

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchVirustotal:
    def __init__(self, word: str, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError('VirusTotal limit must be a positive integer')
        self.key = Core.virustotal_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('virustotal')
        self.word = word
        self.limit = limit
        self.proxy = False
        self.hostnames: set[str] = set()

    async def do_search(self) -> SourceExecutionReport | None:
        headers = {'Accept': 'application/json', 'x-apikey': self.key}
        cursor: str | None = None
        seen_cursors: set[str] = set()
        records_seen = 0
        report = None
        try:
            async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy) as session:
                while records_seen < self.limit:
                    remaining = self.limit - records_seen
                    params: dict[str, int | str] = {'limit': min(40, remaining)}
                    if cursor:
                        params['cursor'] = cursor
                    response = await AsyncFetcher.fetch(
                        session=session,
                        url=f'https://www.virustotal.com/api/v3/domains/{self.word}/subdomains',
                        params=params,
                        json=True,
                        include_metadata=True,
                    )
                    if error := provider_http_error(response):
                        return SourceExecutionReport(*error)
                    assert isinstance(response, FetcherResponse)
                    if not isinstance(response.body, dict):
                        return SourceExecutionReport('failed', 'invalid-response')
                    data = response.body.get('data')
                    meta = response.body.get('meta', {})
                    if not isinstance(data, list) or not isinstance(meta, dict):
                        return SourceExecutionReport('failed', 'invalid-response')
                    page_data = data[:remaining]
                    records_seen += len(page_data)
                    hostnames, malformed = self.parse_hostnames(page_data, self.word)
                    for hostname in sorted(hostnames):
                        if len(self.hostnames) >= self.limit:
                            break
                        self.hostnames.add(hostname)
                    if malformed:
                        report = SourceExecutionReport('failed', 'invalid-response')
                    next_cursor = meta.get('cursor')
                    if not data or not isinstance(next_cursor, str) or not next_cursor:
                        break
                    if next_cursor in seen_cursors:
                        return SourceExecutionReport('failed', 'repeated-cursor')
                    seen_cursors.add(next_cursor)
                    cursor = next_cursor
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')
        return report

    async def get_hostnames(self) -> set[str]:
        return self.hostnames

    @staticmethod
    def parse_hostnames(data: list[Any], word: str) -> tuple[set[str], bool]:
        hostnames: set[str] = set()
        malformed = False

        def add(value: Any) -> None:
            nonlocal malformed
            if not isinstance(value, str):
                malformed = True
                return
            if hostname := normalize_scoped_hostname(value.replace('"', ''), word):
                hostnames.add(hostname)

        for item in data:
            if not isinstance(item, dict):
                malformed = True
                continue
            add(item.get('id'))
            attributes = item.get('attributes', {})
            if not isinstance(attributes, dict):
                malformed = True
                continue
            records = attributes.get('last_dns_records', [])
            if not isinstance(records, list):
                malformed = True
            else:
                for record in records:
                    if not isinstance(record, dict):
                        malformed = True
                    else:
                        add(record.get('value'))
            certificate = attributes.get('last_https_certificate')
            if certificate is None:
                continue
            if not isinstance(certificate, dict) or not isinstance(certificate.get('extensions'), dict):
                malformed = True
                continue
            names = certificate['extensions'].get('subject_alternative_name', [])
            if not isinstance(names, list):
                malformed = True
                continue
            for name in names:
                add(name)
        return hostnames, malformed

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
