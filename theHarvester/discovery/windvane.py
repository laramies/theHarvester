from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

logger = logging.getLogger(__name__)


class SearchWindvane:
    """Use the Windvane API to gather subdomains and domain data.

    API documentation: https://windvane.lichoin.com

    The API provides several endpoints:
    - /ListSubDomain - Subdomain enumeration
    - /ListDNS - DNS history analysis
    - /ListDomainWhois - Historical whois lookup
    - /ListEmail - Domain name email query

    The provider grants full endpoint access and pagination with an API key.
    Unauthenticated requests have limited access.

    Set the key with ``WINDVANE_API_KEY`` or ``search.set_api_key("your-key")``.
    """

    def __init__(self, word: str, limit: int | None = None) -> None:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError('Windvane limit must be a positive integer')
        self.word = word.strip().lower().rstrip('.')
        self.limit = limit
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.totalemails: set = set()
        self.proxy = False
        self.hostname = 'https://windvane.lichoin.com/trpc.backendhub.public.WindvaneService'
        self.api_key = self._get_api_key()

    def _add_host(self, value: object) -> bool:
        if (hostname := normalize_scoped_hostname(value, self.word)) and hostname != self.word:
            self.totalhosts.add(hostname)
            return True
        return False

    def _add_email(self, value: object) -> None:
        if not isinstance(value, str) or '@' not in value:
            return
        local_part, domain = value.rsplit('@', 1)
        if local_part and (normalized_domain := normalize_scoped_hostname(domain, self.word)):
            self.totalemails.add(f'{local_part.lower()}@{normalized_domain}')

    def _get_api_key(self) -> str | None:
        try:
            return Core.windvane_key()
        except Exception:
            # API key is optional for windvane - returns None for limited access
            return None

    @staticmethod
    def _safe_parse_json(payload: object) -> dict:
        # If already a dict, return it; if string, try parse; else return {}
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, str):
            try:
                return json.loads(payload)
            except Exception:
                return {}
        return {}

    @staticmethod
    def _next_page(data: dict[str, Any], page: int, count: int, records: list[object]) -> int | None:
        metadata = [data]
        metadata.extend(
            value for key in ('pagination', 'page_response', 'page_info') if isinstance((value := data.get(key)), dict)
        )
        for section in metadata:
            for key in ('next_page', 'nextPage'):
                if key in section:
                    value = section[key]
                    return int(value) if isinstance(value, int | str) and str(value).isdigit() and int(value) > 0 else None
            for key in ('has_more', 'hasMore'):
                if isinstance(section.get(key), bool):
                    return page + 1 if section[key] else None
            for key in ('total', 'total_count', 'totalCount'):
                if isinstance(section.get(key), int):
                    return page + 1 if page * count < section[key] else None
        return page + 1 if len(records) >= count else None

    async def _paginate(
        self,
        headers: dict[str, str],
        endpoint: str,
        query: dict[str, str],
        page_size: int,
        consume: Callable[[object], object],
    ) -> SourceExecutionReport | None:
        page = 1
        records_seen = 0
        seen_pages: set[str] = set()
        seen_cursors: set[int] = set()
        url = f'{self.hostname}/{endpoint}'
        while self.limit is None or records_seen < self.limit:
            count = min(page_size, self.limit - records_seen) if self.limit is not None else page_size
            request_data: dict[str, object] = {**query, 'page_request': {'page': page, 'count': count}}
            response = await AsyncFetcher.post_fetch(
                url,
                headers=headers,
                data=json.dumps(request_data, separators=(',', ':')),
                proxy=self.proxy,
            )
            if not response:
                return SourceExecutionReport('failed', 'transport-error')
            response_data = self._safe_parse_json(response)
            if not response_data:
                return SourceExecutionReport('failed', 'invalid-response')
            if response_data.get('code') != 0:
                logger.info(f'Windvane {endpoint} API returned code {response_data.get("code")}')
                return (
                    SourceExecutionReport('partial', 'provider-limit')
                    if records_seen
                    else SourceExecutionReport('failed', 'provider-error')
                )
            data = response_data.get('data')
            if not isinstance(data, dict) or not isinstance(data.get('list'), list):
                return SourceExecutionReport('failed', 'invalid-response')
            records = data['list']
            if not records:
                return None
            signature = json.dumps(records, sort_keys=True, default=str)
            if signature in seen_pages:
                return SourceExecutionReport('partial', 'repeated-page')
            seen_pages.add(signature)
            accepted = records[: self.limit - records_seen] if self.limit is not None else records
            for record in accepted:
                consume(record)
            records_seen += len(accepted)
            if self.limit is not None and records_seen >= self.limit:
                return SourceExecutionReport('completed', 'result-limit')
            next_page = self._next_page(data, page, count, records)
            if next_page is None:
                return None
            if next_page == page or next_page in seen_cursors:
                return SourceExecutionReport('partial', 'repeated-cursor')
            seen_cursors.add(next_page)
            page = next_page
        return None

    async def do_search(self) -> SourceExecutionReport | None:
        """Query the Windvane endpoints used by this source."""
        try:
            headers = {'User-agent': Core.get_user_agent(), 'Content-Type': 'application/json', 'Accept': 'application/json'}

            # Add API key if available
            if self.api_key:
                headers['X-Api-Key'] = self.api_key

                # With API key, use full API endpoints
                reports = [
                    await self._search_subdomains(headers),
                    await self._search_dns_history(headers),
                    await self._search_emails(headers),
                ]
            else:
                # Without API key, use the provider's limited endpoint only.
                logger.info('[*] Windvane API key not found. Using limited unauthenticated access.')
                reports = [await self._search_subdomains_limited(headers)]

            retained = [report for report in reports if report is not None]
            return next((report for report in retained if report.status != 'completed'), retained[0] if retained else None)

        except Exception as e:
            logger.info(f'Windvane API error: {e}')
            return SourceExecutionReport('failed', 'transport-error')

    async def _search_subdomains(self, headers: dict[str, str]) -> SourceExecutionReport | None:
        """Search for subdomains with ``/ListSubDomain``."""
        return await self._paginate(
            headers,
            'ListSubDomain',
            {'domain': self.word},
            30,
            lambda item: self._add_host(item.get('domain')) if isinstance(item, dict) else None,
        )

    async def _search_dns_history(self, headers: dict[str, str]) -> SourceExecutionReport | None:
        """Collect subdomains and IP addresses from ``/ListDNS`` history."""

        def consume(record: object) -> None:
            if not isinstance(record, dict):
                return
            answer = record.get('answer', '')
            if (
                self._add_host(record.get('domain'))
                and record.get('answer_type') == 'A'
                and isinstance(answer, str)
                and self._is_valid_ip(answer)
            ):
                self.totalips.add(answer)

        return await self._paginate(headers, 'ListDNS', {'domain': self.word}, 30, consume)

    async def _search_emails(self, headers: dict[str, str]) -> SourceExecutionReport | None:
        """Search for email addresses with ``/ListEmail``."""

        def consume(item: object) -> None:
            if isinstance(item, dict):
                self._add_email(item.get('email'))
                self._add_host(item.get('domain'))

        return await self._paginate(headers, 'ListEmail', {'email': self.word}, 50, consume)

    async def _search_subdomains_limited(self, headers: dict[str, str]) -> SourceExecutionReport | None:
        """Search the unauthenticated subdomain endpoints."""
        report = await self._paginate(
            headers,
            'ListSubDomain',
            {'domain': self.word},
            10,
            lambda item: self._add_host(item.get('domain')) if isinstance(item, dict) else None,
        )
        logger.info(f'[*] Found {len(self.totalhosts)} subdomains with limited access')
        return report

    def set_api_key(self, api_key: str) -> None:
        """Set the API key for authenticated requests.

        Args:
            api_key: Windvane API key.

        """
        self.api_key = api_key

    def _is_valid_ip(self, ip: str) -> bool:
        """Return whether a string is a valid IP address."""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except ValueError, TypeError:
            return False

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def get_emails(self) -> set:
        return self.totalemails

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        """Run the Windvane search.

        Args:
            proxy: Whether to use a proxy for requests.

        """
        self.proxy = proxy

        # API key is already set via _get_api_key() method

        return await self.do_search()
