from __future__ import annotations

import base64
import math
import re
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport, SourceReportStatus
from theHarvester.parsers import myparser


class SearchZoomEye:
    PAGE_SIZE = 10_000
    RESPONSE_FIELDS = ','.join(
        (
            'ip',
            'domain',
            'hostname',
            'rdns',
            'asn',
            'url',
            'banner',
            'header',
            'body',
            'ssl',
        )
    )
    URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')

    def __init__(self, word: str, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError('ZoomEye limit must be a positive integer')
        key = Core.zoomeye_key()
        if not isinstance(key, str) or not key.strip():
            raise MissingKey('zoomeye')
        self.word = word
        self.target = word.strip().lower().removeprefix('www.').rstrip('.')
        self.limit = limit
        self.key = key
        self.baseurl = 'https://api.zoomeye.ai/v2/search'
        self.proxy = False
        self.totalasns: set[str] = set()
        self.totalhosts: set[str] = set()
        self.urls: set[str] = set()
        self.totalips: set[str] = set()
        self.totalemails: set[str] = set()
        self._report: SourceExecutionReport | None = None

    def _stop(self, status: SourceReportStatus, reason: str) -> None:
        self._report = SourceExecutionReport(status, reason)

    def _normalize_url(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = urlsplit(value.rstrip('),.;'))
        except ValueError:
            return None
        hostname = normalize_scoped_hostname(parsed.hostname, self.target)
        if parsed.scheme not in {'http', 'https'} or not parsed.netloc or hostname is None:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        try:
            port = f':{parsed.port}' if parsed.port is not None else ''
        except ValueError:
            return None
        return urlunsplit((parsed.scheme, f'{hostname}{port}', parsed.path, parsed.query, ''))

    async def _fetch_page(self, session: Any, page: int, page_size: int) -> dict[str, Any] | None:
        query = base64.b64encode(f'domain="{self.target}"'.encode()).decode()
        response = await AsyncFetcher.post_fetch(
            self.baseurl,
            session=session,
            json=True,
            include_metadata=True,
            json_body={
                'qbase64': query,
                'sub_type': 'all',
                'page': page,
                'pagesize': page_size,
                'fields': self.RESPONSE_FIELDS,
            },
        )
        if error := provider_http_error(response):
            self._stop(*error)
            return None
        assert isinstance(response, FetcherResponse)
        if not isinstance(response.body, dict):
            self._stop('failed', 'invalid-response')
            return None
        if response.body.get('code') != 60000:
            self._stop('failed', 'provider-error')
            return None
        data = response.body.get('data')
        total = response.body.get('total')
        if not isinstance(data, list) or isinstance(total, bool) or not isinstance(total, int) or total < 0:
            self._stop('failed', 'invalid-response')
            return None
        return response.body

    async def do_search(self, session: Any) -> None:
        page_size = min(self.PAGE_SIZE, self.limit)
        first = await self._fetch_page(session, 1, page_size)
        if first is None:
            return
        await self._store_matches(first['data'][:page_size])
        page_limit = math.ceil(min(first['total'], self.limit) / page_size) if first['total'] else 1
        for page in range(2, page_limit + 1):
            remaining = self.limit - ((page - 1) * page_size)
            response = await self._fetch_page(session, page, page_size)
            if response is None:
                return
            await self._store_matches(response['data'][:remaining])

    async def _store_matches(self, matches: list[Any]) -> None:
        hostnames, emails, ips, asns, urls, malformed = await self.parse_matches(matches)
        self.totalhosts.update(hostnames)
        self.totalemails.update(emails)
        self.totalips.update(ips)
        self.totalasns.update(asns)
        self.urls.update(urls)
        if malformed:
            self._stop('failed', 'invalid-response')

    async def parse_matches(
        self,
        matches: list[Any],
    ) -> tuple[set[str], set[str], set[str], set[str], set[str], bool]:
        ips: set[str] = set()
        urls: set[str] = set()
        hostnames: set[str] = set()
        asns: set[str] = set()
        emails: set[str] = set()
        malformed = False

        for match in matches:
            if not isinstance(match, dict):
                malformed = True
                continue
            raw_ip = match.get('ip')
            if raw_ip is not None:
                try:
                    ips.add(str(ip_address(str(raw_ip).strip())))
                except ValueError:
                    malformed = True

            raw_asn = match.get('asn')
            if raw_asn is not None:
                try:
                    asns.add(f'AS{int(str(raw_asn).removeprefix("AS"))}')
                except ValueError:
                    malformed = True

            for field in ('domain', 'hostname', 'rdns'):
                value = match.get(field)
                if value is None:
                    continue
                if not isinstance(value, str):
                    malformed = True
                elif (hostname := normalize_scoped_hostname(value, self.target)) and hostname != self.target:
                    hostnames.add(hostname)

            if raw_url := match.get('url'):
                if normalized_url := self._normalize_url(raw_url):
                    urls.add(normalized_url)
                    if url_hostname := normalize_scoped_hostname(urlsplit(normalized_url).hostname, self.target):
                        if url_hostname != self.target:
                            hostnames.add(url_hostname)
                elif isinstance(raw_url, str):
                    malformed = True

            text_values: list[str] = []
            for field in ('banner', 'header', 'body', 'ssl'):
                value = match.get(field)
                if value is None:
                    continue
                if isinstance(value, str):
                    text_values.append(value)
                else:
                    malformed = True
            if not text_values:
                continue
            content = '\n'.join(text_values)
            parser = myparser.Parser(content, self.word)
            emails.update(await parser.emails())
            parser = myparser.Parser(content, self.word)
            hostnames.update(hostname for hostname in await parser.hostnames() if hostname != self.target)
            for candidate in self.URL_PATTERN.findall(content):
                if normalized_url := self._normalize_url(candidate):
                    urls.add(normalized_url)

        return hostnames, emails, ips, asns, urls, malformed

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        self._report = None
        try:
            async with AsyncFetcher.open_session(
                headers={'API-KEY': self.key, 'Content-Type': 'application/json'},
                proxy=proxy,
            ) as session:
                await self.do_search(session)
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')
        return self._report

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_emails(self) -> set[str]:
        return self.totalemails

    async def get_ips(self) -> set[str]:
        return self.totalips

    async def get_asns(self) -> set[str]:
        return self.totalasns

    async def get_urls(self) -> set[str]:
        return self.urls
