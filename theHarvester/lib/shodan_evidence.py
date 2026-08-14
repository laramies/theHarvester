from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Self

from theHarvester.lib.result_values import normalize_asn


def _optional_text(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f'Shodan {field} must be a string')
    return value.strip() or None


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f'Shodan {field} must be an array of strings')
    return tuple(sorted({item.strip() for item in value if item.strip()}))


def _hostname_tuple(value: object, field: str) -> tuple[str, ...]:
    return tuple(sorted({item.casefold().rstrip('.') for item in _string_tuple(value, field)} - {''}))


@dataclass(frozen=True, slots=True)
class ShodanServiceObservation:
    port: int
    transport: str
    product: str | None = None
    version: str | None = None
    observed_at: str | None = None
    cpes: tuple[str, ...] = ()
    http_title: str | None = None
    http_server: str | None = None
    http_components: tuple[str, ...] = ()
    tls_subject_cn: str | None = None
    tls_issuer_cn: str | None = None
    tls_expires_at: str | None = None
    tls_sha256: str | None = None
    tls_jarm: str | None = None

    @classmethod
    def from_record(cls, record: object) -> Self:
        if not isinstance(record, dict):
            raise ValueError('Shodan services must be objects')
        allowed = {'port', 'transport', 'product', 'version', 'observed_at', 'cpes', 'http', 'tls'}
        if set(record) - allowed:
            raise ValueError('Shodan service contains unsupported fields')
        port = record.get('port')
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('Shodan service port must be between 1 and 65535')
        transport = _optional_text(record.get('transport'), 'service transport')
        if transport is None or transport.casefold() not in {'tcp', 'udp'}:
            raise ValueError('Shodan service transport must be tcp or udp')

        http = record.get('http')
        if http is not None and (not isinstance(http, dict) or set(http) - {'title', 'server', 'components'}):
            raise ValueError('Shodan HTTP evidence contains unsupported fields')
        tls = record.get('tls')
        if tls is not None and (
            not isinstance(tls, dict) or set(tls) - {'subject_cn', 'issuer_cn', 'expires_at', 'sha256', 'jarm'}
        ):
            raise ValueError('Shodan TLS evidence contains unsupported fields')

        return cls(
            port=port,
            transport=transport.casefold(),
            product=_optional_text(record.get('product'), 'service product'),
            version=_optional_text(record.get('version'), 'service version'),
            observed_at=_optional_text(record.get('observed_at'), 'service observation time'),
            cpes=_string_tuple(record.get('cpes'), 'service CPEs'),
            http_title=_optional_text(http.get('title'), 'HTTP title') if isinstance(http, dict) else None,
            http_server=_optional_text(http.get('server'), 'HTTP server') if isinstance(http, dict) else None,
            http_components=_string_tuple(http.get('components'), 'HTTP components') if isinstance(http, dict) else (),
            tls_subject_cn=_optional_text(tls.get('subject_cn'), 'TLS subject CN') if isinstance(tls, dict) else None,
            tls_issuer_cn=_optional_text(tls.get('issuer_cn'), 'TLS issuer CN') if isinstance(tls, dict) else None,
            tls_expires_at=_optional_text(tls.get('expires_at'), 'TLS expiry') if isinstance(tls, dict) else None,
            tls_sha256=_optional_text(tls.get('sha256'), 'TLS SHA-256') if isinstance(tls, dict) else None,
            tls_jarm=_optional_text(tls.get('jarm'), 'TLS JARM') if isinstance(tls, dict) else None,
        )

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.port,
            self.transport,
            self.observed_at or '',
            self.product or '',
            self.version or '',
            self.http_title or '',
            self.http_server or '',
            self.http_components,
            self.tls_subject_cn or '',
            self.tls_issuer_cn or '',
            self.tls_expires_at or '',
            self.tls_sha256 or '',
            self.tls_jarm or '',
            self.cpes,
        )

    def to_record(self) -> dict[str, object]:
        record: dict[str, object] = {'port': self.port, 'transport': self.transport}
        for field, value in (
            ('product', self.product),
            ('version', self.version),
            ('observed_at', self.observed_at),
        ):
            if value is not None:
                record[field] = value
        if self.cpes:
            record['cpes'] = list(self.cpes)
        http: dict[str, object] = {}
        if self.http_title is not None:
            http['title'] = self.http_title
        if self.http_server is not None:
            http['server'] = self.http_server
        if self.http_components:
            http['components'] = list(self.http_components)
        if http:
            record['http'] = http
        tls: dict[str, str] = {}
        for field, value in (
            ('subject_cn', self.tls_subject_cn),
            ('issuer_cn', self.tls_issuer_cn),
            ('expires_at', self.tls_expires_at),
            ('sha256', self.tls_sha256),
            ('jarm', self.tls_jarm),
        ):
            if value is not None:
                tls[field] = value
        if tls:
            record['tls'] = tls
        return record


@dataclass(frozen=True, slots=True)
class ShodanHostObservation:
    ip: str
    services: tuple[ShodanServiceObservation, ...]
    asn: str | None = None
    organization: str | None = None
    isp: str | None = None
    hostnames: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()

    @classmethod
    def from_record(cls, value: str, details: object) -> Self:
        if not isinstance(value, str) or '%' in value:
            raise ValueError('Shodan host value must be a canonical IP address')
        try:
            canonical_ip = str(ip_address(value.strip()))
        except ValueError as error:
            raise ValueError('Shodan host value must be a canonical IP address') from error
        if not isinstance(details, dict):
            raise ValueError('Shodan host details must be an object')
        allowed = {'asn', 'organization', 'isp', 'hostnames', 'domains', 'services'}
        if set(details) - allowed:
            raise ValueError('Shodan host details contain unsupported fields')
        raw_services = details.get('services')
        if not isinstance(raw_services, list) or not raw_services:
            raise ValueError('Shodan host details require at least one service')
        services = tuple(
            sorted(
                {ShodanServiceObservation.from_record(service) for service in raw_services},
                key=ShodanServiceObservation.sort_key,
            )
        )
        raw_asn = _optional_text(details.get('asn'), 'ASN')
        return cls(
            ip=canonical_ip,
            services=services,
            asn=normalize_asn(raw_asn) if raw_asn is not None else None,
            organization=_optional_text(details.get('organization'), 'organization'),
            isp=_optional_text(details.get('isp'), 'ISP'),
            hostnames=_hostname_tuple(details.get('hostnames'), 'hostnames'),
            domains=_hostname_tuple(details.get('domains'), 'domains'),
        )

    def sort_key(self) -> tuple[int, int]:
        address = ip_address(self.ip)
        return address.version, int(address)

    def to_details(self) -> dict[str, object]:
        details: dict[str, object] = {}
        for field, value in (
            ('asn', self.asn),
            ('organization', self.organization),
            ('isp', self.isp),
        ):
            if value is not None:
                details[field] = value
        if self.hostnames:
            details['hostnames'] = list(self.hostnames)
        if self.domains:
            details['domains'] = list(self.domains)
        details['services'] = [service.to_record() for service in self.services]
        return details


def canonical_shodan_hosts(
    observations: tuple[ShodanHostObservation, ...] | list[ShodanHostObservation],
) -> tuple[ShodanHostObservation, ...]:
    by_ip: dict[str, ShodanHostObservation] = {}
    for observation in observations:
        existing = by_ip.get(observation.ip)
        if existing is not None and existing != observation:
            raise ValueError(f'Shodan host {observation.ip} has conflicting evidence')
        by_ip[observation.ip] = observation
    return tuple(sorted(by_ip.values(), key=ShodanHostObservation.sort_key))
