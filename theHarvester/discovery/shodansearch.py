import asyncio
import logging
import re
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
_CERTIFICATE_HOSTNAME = re.compile(
    r'(?i)(?<![a-z0-9-])(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?![a-z0-9.-])'
)


class SearchShodan:
    """Collect Shodan host data and retain ``asn`` + ``org`` attribution.

    Shodan documents ``org`` and ``isp`` as separate Host API fields. The
    organization attribution uses ``org`` and stays linked to the queried IP;
    ``isp`` remains ordinary Shodan output and is not treated as equivalent.
    """

    API_BASE_URL = 'https://api.shodan.io/shodan/host'
    SEARCH_URL = f'{API_BASE_URL}/search'
    SEARCH_FIELDS = ','.join(
        (
            'ip_str',
            'asn',
            'domains',
            'hostnames',
            'isp',
            'org',
            'port',
            'transport',
            'product',
            'version',
            'timestamp',
            'cpe',
            'http.title',
            'http.server',
            'http.components',
            'ssl.jarm',
            'ssl.cert.subject',
            'ssl.cert.issuer',
            'ssl.cert.expires',
            'ssl.cert.fingerprint',
            'ssl.cert.extensions',
        )
    )
    # Preserve the official SDK's one-request-per-second pacing without retaining its blocking transport.
    REQUEST_INTERVAL_SECONDS = 1.0
    REQUEST_TIMEOUT_SECONDS: int | None = None

    def __init__(self, word: str | None = None) -> None:
        self.word = word.strip().lower().rstrip('.') if word is not None else None
        if self.word is not None and (self.word.startswith('*.') or _CERTIFICATE_HOSTNAME.fullmatch(self.word) is None):
            raise ValueError('Shodan discovery target must be a hostname')
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

    async def _fetch_json(self, url: str, params: dict[str, object], proxy: bool) -> FetcherResponse:
        loop = asyncio.get_running_loop()
        delay = self._next_request_at - loop.time()
        if delay > 0:
            await asyncio.sleep(delay)
        self._next_request_at = loop.time() + self.REQUEST_INTERVAL_SECONDS
        return await AsyncFetcher.fetch_json(
            url,
            params=params,
            proxy=proxy,
            request_timeout=self.REQUEST_TIMEOUT_SECONDS,
        )

    async def _fetch_host(self, ip: str, proxy: bool) -> FetcherResponse:
        return await self._fetch_json(f'{self.API_BASE_URL}/{ip}', {'key': self.key}, proxy)

    def _certificate_name(self, value: object) -> str | None:
        if not isinstance(value, str) or not (candidate := value.strip().casefold().rstrip('.')):
            return None
        if _CERTIFICATE_HOSTNAME.fullmatch(candidate) is None:
            return None
        wildcard = candidate.startswith('*.')
        hostname = candidate.removeprefix('*.')
        if self.scope is not None:
            hostname = normalize_scoped_hostname(hostname, self.scope) or ''
            if not hostname:
                return None
        else:
            try:
                ip_address(hostname)
            except ValueError:
                pass
            else:
                return None
        return f'*.{hostname}' if wildcard else hostname

    def _certificate_names(self, cert: object) -> tuple[set[str], bool]:
        if not isinstance(cert, dict):
            return set(), cert is not None
        invalid_response = False
        names: set[str] = set()
        subject = cert.get('subject')
        if subject is not None and not isinstance(subject, dict):
            invalid_response = True
        elif isinstance(subject, dict):
            if normalized := self._certificate_name(subject.get('CN')):
                names.add(normalized)

        extensions = cert.get('extensions')
        if extensions is not None and not isinstance(extensions, list):
            invalid_response = True
        elif isinstance(extensions, list):
            for extension in extensions:
                if not isinstance(extension, dict):
                    invalid_response = True
                    continue
                if extension.get('name') != 'subjectAltName':
                    continue
                data = extension.get('data')
                if not isinstance(data, str):
                    invalid_response = True
                    continue
                decoded = re.sub(r'\\x[0-9a-f]{2}', ' ', data, flags=re.IGNORECASE)
                for match in _CERTIFICATE_HOSTNAME.finditer(decoded):
                    if normalized := self._certificate_name(match.group()):
                        names.add(normalized)
        return names, invalid_response

    def _scoped_banner_names(self, banner: dict[str, object]) -> set[str]:
        assert self.scope is not None
        names: set[str] = set()
        for field in ('hostnames', 'domains'):
            values = banner.get(field)
            if isinstance(values, list):
                for value in values:
                    if normalized := normalize_scoped_hostname(value, self.scope):
                        names.add(normalized)
        ssl = banner.get('ssl')
        if isinstance(ssl, dict):
            cert_names, _invalid = self._certificate_names(ssl.get('cert'))
            names.update(cert_names)
        return names

    def _merge_host(self, observation: ShodanHostObservation) -> bool:
        existing = self.shodan_hosts.get(observation.ip)
        if existing is None:
            self.shodan_hosts[observation.ip] = observation
            return False

        invalid_response = False
        scalars: dict[str, str | None] = {}
        for field in ('asn', 'organization', 'isp'):
            previous = getattr(existing, field)
            current = getattr(observation, field)
            if previous is not None and current is not None and previous != current:
                invalid_response = True
            scalars[field] = previous or current
        self.shodan_hosts[observation.ip] = ShodanHostObservation.from_record(
            observation.ip,
            {
                **scalars,
                'hostnames': sorted(set(existing.hostnames) | set(observation.hostnames)),
                'domains': sorted(set(existing.domains) | set(observation.domains)),
                'services': [
                    service.to_record()
                    for service in sorted(
                        set(existing.services) | set(observation.services),
                        key=lambda service: service.sort_key(),
                    )
                ],
            },
        )
        return invalid_response

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
                tls_details: dict[str, object] = {}
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
                    subject_cn = self._certificate_name(subject.get('CN')) if isinstance(subject, dict) else None
                    cert_names, invalid_cert = self._certificate_names(cert)
                    invalid_response = invalid_response or invalid_cert
                    if subject_cn:
                        tls_details['subject_cn'] = subject_cn
                    subject_alt_names = sorted(cert_names - ({subject_cn} if subject_cn else set()))
                    if subject_alt_names:
                        tls_details['subject_alt_names'] = subject_alt_names
                    for field, source in (
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
        if self.scope is not None:
            domain_values = sorted(
                {normalized for value in domain_values if (normalized := normalize_scoped_hostname(value, self.scope))}
            )
            hostname_values = sorted(
                {normalized for value in hostname_values if (normalized := normalize_scoped_hostname(value, self.scope))}
            )
            self.totalhosts.update(value for value in domain_values + hostname_values if value != self.scope)
            for service in services:
                tls = service.get('tls')
                if not isinstance(tls, dict):
                    continue
                for field in ('subject_cn', 'subject_alt_names'):
                    tls_value = tls.get(field)
                    values = tls_value if isinstance(tls_value, list) else [tls_value]
                    self.totalhosts.update(
                        name for name in values if isinstance(name, str) and not name.startswith('*.') and name != self.scope
                    )
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
        invalid_response = self._merge_host(shodan_host) or invalid_response
        stored_host = self.shodan_hosts[ip]
        self.tracker[ip] = stored_host.to_details()

        if stored_host.asn and stored_host.organization:
            self.asn_attributions.add(
                AsnAttributionObservation(
                    'action',
                    'shodan',
                    stored_host.asn,
                    stored_host.organization,
                    'ip',
                    ip,
                    datetime.now(UTC),
                )
            )
        return invalid_response

    async def _search_target(self, proxy: bool) -> set[str]:
        assert self.scope is not None
        error_types: set[str] = set()
        for query in (f'hostname:{self.scope}', f'ssl:{self.scope}'):
            page = 1
            received = 0
            while True:
                try:
                    response = await self._fetch_json(
                        self.SEARCH_URL,
                        {
                            'key': self.key,
                            'query': query,
                            'page': page,
                            'minify': 'false',
                            'fields': self.SEARCH_FIELDS,
                        },
                        proxy,
                    )
                except ResponseStreamError as error:
                    error_types.add(
                        {
                            'invalid-response': 'InvalidResponseError',
                            'response-limit': 'ResponseLimitError',
                            'transport-error': 'TransportError',
                        }[error.reason]
                    )
                    break
                except Exception as error:
                    error_types.add(type(error).__name__)
                    break
                if not 200 <= response.status < 300:
                    error_types.add(f'HTTP{response.status}Error')
                    break
                if not isinstance(response.body, dict):
                    error_types.add('InvalidResponseError')
                    break
                matches = response.body.get('matches')
                total = response.body.get('total')
                if not isinstance(matches, list) or isinstance(total, bool) or not isinstance(total, int) or total < 0:
                    error_types.add('InvalidResponseError')
                    break
                for match in matches:
                    if not isinstance(match, dict):
                        error_types.add('InvalidResponseError')
                        continue
                    if not self._scoped_banner_names(match):
                        continue
                    ip_value = match.get('ip_str')
                    if not isinstance(ip_value, str):
                        error_types.add('InvalidResponseError')
                        continue
                    try:
                        ip = str(ip_address(ip_value))
                        if self._record_host(ip, {**match, 'data': [match]}):
                            error_types.add('InvalidResponseError')
                    except (TypeError, ValueError):
                        error_types.add('InvalidResponseError')
                received += len(matches)
                if not matches:
                    if received < total:
                        error_types.add('InvalidResponseError')
                    break
                if received >= total:
                    break
                page += 1
        return error_types

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
        dns_stop_reason: str | None = None
        try:
            resolved_ips = await resolve_ip_addresses(self.word, family=socket.AF_INET)
            if not resolved_ips:
                raise ValueError('target has no IPv4 addresses')
        except TimeoutError:
            resolved_ips = ()
            dns_stop_reason = 'dns-timeout'
        except aiodns.error.DNSError as error:
            resolved_ips = ()
            dns_stop_reason = (
                'dns-timeout' if error.args and error.args[0] == aiodns.error.ARES_ETIMEOUT else 'dns-resolution-failed'
            )
        except ValueError:
            resolved_ips = ()
            dns_stop_reason = 'dns-resolution-failed'

        provider_error_types = await self._search_target(proxy)
        for resolved_ip in resolved_ips:
            await self.search_ip(resolved_ip, proxy=proxy)
            if self.error_type is not None:
                provider_error_types.add(self.error_type)

        self.error_type = next(iter(sorted(provider_error_types)), None)
        retained_evidence = bool(self.totalhosts or self.shodan_hosts)
        if dns_stop_reason is not None:
            self.execution_status = 'partial' if retained_evidence else 'failed'
            self.stop_reason = dns_stop_reason
            return
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
