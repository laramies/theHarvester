import asyncio
import logging
import socket
from collections import OrderedDict
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import cast

import aiodns

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.asn_attribution import AsnAttributionObservation
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.hostchecker import resolve_ip_addresses
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.shodan_evidence import ShodanHostObservation, canonical_shodan_hosts

logger = logging.getLogger(__name__)

HostResult = dict[str, object]


class SearchShodan:
    """Collect Shodan host data and retain ``asn`` + ``org`` attribution.

    Shodan documents ``org`` and ``isp`` as separate Host API fields. The
    organization attribution uses ``org`` and stays linked to the queried IP;
    ``isp`` remains ordinary Shodan output and is not treated as equivalent.
    """

    API_BASE_URL = 'https://api.shodan.io/shodan/host'
    # Preserve the official SDK's one-request-per-second pacing without retaining its blocking transport.
    REQUEST_INTERVAL_SECONDS = 1.0
    REQUEST_TIMEOUT_SECONDS: int | None = None

    def __init__(self, word: str | None = None) -> None:
        self.word = word.strip().lower().rstrip('.') if word is not None else None
        self.scope = self.word.removeprefix('www.') if self.word is not None else None
        self.key = Core.shodan_key()
        if self.key is None:
            raise MissingKey('Shodan')
        self.tracker: OrderedDict[str, HostResult | str] = OrderedDict()
        self.shodan_hosts: dict[str, ShodanHostObservation] = {}
        self.error_type: str | None = None
        self.asn_attributions: set[AsnAttributionObservation] = set()
        self.totalhosts: set[str] = set()
        self.execution_status: str | None = None
        self.stop_reason: str | None = None
        self._next_request_at = 0.0

    async def _fetch_host(self, ip: str, proxy: bool) -> FetcherResponse:
        loop = asyncio.get_running_loop()
        delay = self._next_request_at - loop.time()
        if delay > 0:
            await asyncio.sleep(delay)
        self._next_request_at = loop.time() + self.REQUEST_INTERVAL_SECONDS
        return await AsyncFetcher.fetch_json(
            f'{self.API_BASE_URL}/{ip}',
            params={'key': self.key},
            proxy=proxy,
            request_timeout=self.REQUEST_TIMEOUT_SECONDS,
        )

    def _record_host(self, ip: str, results: dict[str, object]) -> bool:
        data = results.get('data')
        if data == []:
            logger.info(f'Shodan: No data found for IP {ip}')
            return False
        if not isinstance(data, list) or not data:
            raise ValueError('invalid Shodan host response')

        invalid_response = False

        def normalized_string(value: object) -> str:
            nonlocal invalid_response
            if value is None:
                return ''
            if not isinstance(value, str):
                invalid_response = True
                return ''
            normalized = value.strip()
            return '' if normalized == 'None' else normalized

        def normalized_strings(value: object) -> list[str]:
            nonlocal invalid_response
            if value is None:
                return []
            if not isinstance(value, list):
                invalid_response = True
                return []
            if any(not isinstance(item, str) for item in value):
                invalid_response = True
            return sorted({normalized_string(item) for item in value if isinstance(item, str)} - {''})

        services: list[dict[str, object]] = []
        for banner in data:
            if not isinstance(banner, dict):
                invalid_response = True
                continue
            port = banner.get('port')
            transport = normalized_string(banner.get('transport')).casefold()
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                invalid_response = True
                continue
            if transport not in {'tcp', 'udp'}:
                invalid_response = True
                continue

            service: dict[str, object] = {'port': port, 'transport': transport}
            for provider_field, evidence_field in (
                ('product', 'product'),
                ('version', 'version'),
                ('timestamp', 'observed_at'),
            ):
                if value := normalized_string(banner.get(provider_field)):
                    service[evidence_field] = value

            if cpe_values := normalized_strings(banner.get('cpe')):
                service['cpes'] = cpe_values

            http = banner.get('http')
            if isinstance(http, dict):
                http_details: dict[str, object] = {}
                for field in ('title', 'server'):
                    if value := normalized_string(http.get(field)):
                        http_details[field] = value
                components = http.get('components')
                if isinstance(components, dict) and (
                    component_values := sorted({normalized_string(component) for component in components} - {''})
                ):
                    http_details['components'] = component_values
                elif components is not None and not isinstance(components, dict):
                    invalid_response = True
                if http_details:
                    service['http'] = http_details
            elif http is not None:
                invalid_response = True

            ssl = banner.get('ssl')
            if isinstance(ssl, dict):
                tls_details: dict[str, str] = {}
                if jarm := normalized_string(ssl.get('jarm')):
                    tls_details['jarm'] = jarm
                cert = ssl.get('cert')
                if isinstance(cert, dict):
                    subject = cert.get('subject')
                    issuer = cert.get('issuer')
                    fingerprint = cert.get('fingerprint')
                    if subject is not None and not isinstance(subject, dict):
                        invalid_response = True
                    if issuer is not None and not isinstance(issuer, dict):
                        invalid_response = True
                    if fingerprint is not None and not isinstance(fingerprint, dict):
                        invalid_response = True
                    for field, source in (
                        ('subject_cn', subject.get('CN') if isinstance(subject, dict) else None),
                        ('issuer_cn', issuer.get('CN') if isinstance(issuer, dict) else None),
                        ('expires_at', cert.get('expires')),
                        ('sha256', fingerprint.get('sha256') if isinstance(fingerprint, dict) else None),
                    ):
                        if value := normalized_string(source):
                            tls_details[field] = value
                elif cert is not None:
                    invalid_response = True
                if tls_details:
                    service['tls'] = tls_details
            elif ssl is not None:
                invalid_response = True

            if service not in services:
                services.append(service)

        if not services:
            raise ValueError('invalid Shodan host response')
        services.sort(
            key=lambda service: (
                cast('int', service['port']),
                str(service['transport']),
                str(service.get('observed_at', '')),
            )
        )

        domain_values = normalized_strings(results.get('domains'))
        hostname_values = normalized_strings(results.get('hostnames'))
        asn = normalized_string(results.get('asn'))
        organization = normalized_string(results.get('org'))
        host_details = {
            'asn': asn,
            'domains': domain_values,
            'hostnames': hostname_values,
            'isp': normalized_string(results.get('isp')),
            'organization': organization,
            'services': services,
        }
        shodan_host = ShodanHostObservation.from_record(ip, host_details)
        self.shodan_hosts[ip] = shodan_host
        self.tracker[ip] = shodan_host.to_details()

        if asn and organization:
            self.asn_attributions.add(
                AsnAttributionObservation(
                    'action',
                    'shodan',
                    asn,
                    organization,
                    'ip',
                    ip,
                    datetime.now(UTC),
                )
            )
        return invalid_response

    async def search_ip(self, ip: str, *, proxy: bool = False) -> OrderedDict[str, HostResult | str]:
        self.error_type = None
        try:
            normalized_ip = str(ip_address(ip.strip()))
        except ValueError:
            self.error_type = 'ValueError'
            self.tracker[ip] = 'Shodan request failed'
            return self.tracker

        try:
            response = await self._fetch_host(normalized_ip, proxy)
            if response.status == 404:
                logger.info(f'{normalized_ip}: Not in Shodan')
                self.tracker[normalized_ip] = 'Not in Shodan'
                return self.tracker
            if not 200 <= response.status < 300:
                self.error_type = f'HTTP{response.status}Error'
                self.tracker[normalized_ip] = 'Shodan request failed'
                return self.tracker
            if not isinstance(response.body, dict):
                self.error_type = 'InvalidResponseError'
                self.tracker[normalized_ip] = 'Shodan request failed'
                return self.tracker
            try:
                if self._record_host(normalized_ip, response.body):
                    self.error_type = 'InvalidResponseError'
            except (TypeError, ValueError):
                self.error_type = 'InvalidResponseError'
                self.tracker[normalized_ip] = 'Shodan request failed'
        except ResponseStreamError as error:
            self.error_type = {
                'invalid-response': 'InvalidResponseError',
                'response-limit': 'ResponseLimitError',
                'transport-error': 'TransportError',
            }[error.reason]
            self.tracker[normalized_ip] = 'Shodan request failed'
        except Exception as error:
            self.error_type = type(error).__name__
            self.tracker[normalized_ip] = 'Shodan request failed'
        return self.tracker

    async def get_asn_attributions(self) -> set[AsnAttributionObservation]:
        return self.asn_attributions

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_shodan_hosts(self) -> tuple[ShodanHostObservation, ...]:
        return canonical_shodan_hosts(list(self.shodan_hosts.values()))

    async def process(self, proxy: bool = False) -> None:
        if self.word is None:
            raise ValueError('A discovery target is required')
        assert self.scope is not None

        self.totalhosts.clear()
        self.execution_status = None
        self.stop_reason = None
        try:
            resolved_ips = await resolve_ip_addresses(self.word, family=socket.AF_INET)
            if not resolved_ips:
                raise ValueError('target has no IPv4 addresses')
        except TimeoutError:
            self.execution_status = 'failed'
            self.stop_reason = 'dns-timeout'
            return
        except aiodns.error.DNSError as error:
            self.execution_status = 'failed'
            self.stop_reason = (
                'dns-timeout' if error.args and error.args[0] == aiodns.error.ARES_ETIMEOUT else 'dns-resolution-failed'
            )
            return
        except ValueError:
            self.execution_status = 'failed'
            self.stop_reason = 'dns-resolution-failed'
            return

        provider_error_types: set[str] = set()
        for resolved_ip in resolved_ips:
            result = await self.search_ip(resolved_ip, proxy=proxy)
            host_data = result.get(resolved_ip)
            if isinstance(host_data, dict):
                hostnames = host_data.get('hostnames')
                if isinstance(hostnames, list):
                    for hostname in hostnames:
                        normalized = normalize_scoped_hostname(hostname, self.scope)
                        if normalized and normalized != self.scope:
                            self.totalhosts.add(normalized)
            if self.error_type is not None:
                provider_error_types.add(self.error_type)

        self.error_type = next(iter(sorted(provider_error_types)), None)
        retained_evidence = bool(self.totalhosts or self.shodan_hosts)
        if provider_error_types:
            self.execution_status = 'partial' if retained_evidence else 'failed'
            if provider_error_types <= {'HTTP401Error', 'HTTP403Error'}:
                self.stop_reason = 'access-denied'
            elif provider_error_types == {'HTTP429Error'}:
                self.stop_reason = 'rate-limited'
            elif len(resolved_ips) == 1:
                self.stop_reason = 'provider-error'
            else:
                self.stop_reason = 'provider-errors'
            return

        self.execution_status = 'completed'
        self.stop_reason = None if retained_evidence else 'no-results'
