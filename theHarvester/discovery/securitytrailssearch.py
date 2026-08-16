from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchSecuritytrail:
    def __init__(self, word: str) -> None:
        self.word = word
        self.key = Core.security_trails_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('Securitytrail')
        self.api = 'https://api.securitytrails.com/v1/'
        self.info: tuple[set[str], set[str]] = (set(), set())
        self.proxy = False
        self.domain_data: dict[str, Any] = {}
        self.subdomains_data: dict[str, Any] = {}
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self.info[0] or self.info[1] else status
        self.stop_reason = reason

    def _body(self, response: Any) -> dict[str, Any] | None:
        if error := provider_http_error(response):
            self._stop(*error)
            return None
        assert isinstance(response, FetcherResponse)
        if not isinstance(response.body, dict):
            self._stop('failed', 'invalid-response')
            return None
        return response.body

    def _parse_domain(self, data: dict[str, Any]) -> bool:
        malformed = False
        current_dns = data.get('current_dns', {})
        if not isinstance(current_dns, dict):
            return True
        ips = self.info[0]
        for record_type, key in (('a', 'ip'), ('aaaa', 'ipv6')):
            records = current_dns.get(record_type, {})
            if not isinstance(records, dict) or not isinstance(records.get('values', []), list):
                malformed = True
                continue
            for record in records.get('values', []):
                if not isinstance(record, dict) or not isinstance(record.get(key), str):
                    malformed = True
                    continue
                try:
                    ips.add(str(ip_address(record[key].strip())))
                except ValueError:
                    malformed = True
        return malformed

    def _parse_subdomains(self, data: dict[str, Any]) -> bool:
        values = data.get('subdomains')
        if not isinstance(values, list):
            return True
        malformed = False
        hostnames = self.info[1]
        for value in values:
            if not isinstance(value, str) or not value.strip():
                malformed = True
                continue
            if hostname := normalize_scoped_hostname(f'{value}.{self.word}', self.word):
                hostnames.add(hostname)
        return malformed

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        headers = {'APIKEY': self.key, 'Accept': 'application/json'}
        try:
            async with AsyncFetcher.open_session(headers=headers, proxy=proxy) as session:
                domain_response = await AsyncFetcher.fetch(
                    session=session,
                    url=f'{self.api}domain/{self.word}',
                    json=True,
                    include_metadata=True,
                )
                domain_body = self._body(domain_response)
                if domain_body is None:
                    return
                self.domain_data = domain_body
                malformed = self._parse_domain(domain_body)

                subdomain_response = await AsyncFetcher.fetch(
                    session=session,
                    url=f'{self.api}domain/{self.word}/subdomains',
                    json=True,
                    include_metadata=True,
                )
                subdomain_body = self._body(subdomain_response)
                if subdomain_body is None:
                    return
                self.subdomains_data = subdomain_body
                malformed = self._parse_subdomains(subdomain_body) or malformed
        except Exception:
            self._stop('failed', 'transport-error')
            return
        if malformed:
            self._stop('failed', 'invalid-response')
        if self.execution_status is None:
            self.execution_status = 'completed'
            self.stop_reason = None if self.info[0] or self.info[1] else 'no-results'

    async def get_ips(self) -> set[str]:
        return self.info[0]

    async def get_hostnames(self) -> set[str]:
        return self.info[1]
