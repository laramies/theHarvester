from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Literal, Self, cast

from theHarvester.lib.hostnames import normalize_hostname

TakeoverClassification = Literal['vulnerable-indicator', 'unverified-indicator', 'edge-case']
TakeoverCandidateStatus = Literal['indicator', 'no-indicator', 'inconclusive']
TakeoverRcode = Literal['NOERROR', 'NXDOMAIN', 'NODATA', 'ERROR']
HttpScheme = Literal['http', 'https']

_CLASSIFICATIONS = {'vulnerable-indicator', 'unverified-indicator', 'edge-case'}
_STATUSES = {'indicator', 'no-indicator', 'inconclusive'}
_RCODES = {'NOERROR', 'NXDOMAIN', 'NODATA', 'ERROR'}
_SCHEMES = {'http', 'https'}


def _required_text(value: object, field: str, *, limit: int = 512) -> str:
    if not isinstance(value, str) or not (text := value.strip()) or len(text) > limit:
        raise ValueError(f'takeover {field} must be a non-empty string of at most {limit} characters')
    return text


def _optional_text(value: object, field: str, *, limit: int = 2048) -> str | None:
    if value is None:
        return None
    return _required_text(value, field, limit=limit)


@dataclass(frozen=True, slots=True)
class TakeoverDNSOutcome:
    """One resolver's DNS relationship evidence for an in-scope hostname."""

    resolver: str
    cname_chain: tuple[str, ...]
    terminal_rcode: TakeoverRcode
    error_type: str | None = None

    def __post_init__(self) -> None:
        try:
            canonical_resolver = str(ip_address(self.resolver))
        except ValueError as error:
            raise ValueError('takeover resolver must be a canonical IP address') from error
        canonical_chain = tuple(normalize_hostname(item) for item in self.cname_chain)
        if canonical_chain != self.cname_chain or len(set(canonical_chain)) != len(canonical_chain):
            raise ValueError('takeover CNAME chain must be canonical and contain no repeats')
        if self.terminal_rcode not in _RCODES:
            raise ValueError('takeover terminal RCODE is not supported')
        object.__setattr__(self, 'resolver', canonical_resolver)
        object.__setattr__(self, 'error_type', _optional_text(self.error_type, 'DNS error type'))
        if self.terminal_rcode == 'ERROR' and self.error_type is None:
            raise ValueError('takeover DNS ERROR outcomes require an error type')

    @classmethod
    def from_record(cls, record: object) -> Self:
        if not isinstance(record, dict) or set(record) - {
            'resolver',
            'cname_chain',
            'terminal_rcode',
            'error_type',
        }:
            raise ValueError('takeover DNS evidence contains unsupported fields')
        raw_chain = record.get('cname_chain', [])
        if not isinstance(raw_chain, list) or any(not isinstance(item, str) for item in raw_chain):
            raise ValueError('takeover CNAME chain must be an array of hostnames')
        return cls(
            resolver=_required_text(record.get('resolver'), 'resolver'),
            cname_chain=tuple(raw_chain),
            terminal_rcode=cast('TakeoverRcode', _required_text(record.get('terminal_rcode'), 'terminal RCODE')),
            error_type=_optional_text(record.get('error_type'), 'DNS error type'),
        )

    def to_record(self) -> dict[str, object]:
        record: dict[str, object] = {
            'resolver': self.resolver,
            'cname_chain': list(self.cname_chain),
            'terminal_rcode': self.terminal_rcode,
        }
        if self.error_type is not None:
            record['error_type'] = self.error_type
        return record

    def sort_key(self) -> tuple[object, ...]:
        return self.resolver, self.cname_chain, self.terminal_rcode, self.error_type or ''


@dataclass(frozen=True, slots=True)
class TakeoverHTTPOutcome:
    """One bounded request outcome against the authorized hostname."""

    scheme: HttpScheme
    status: int | None = None
    location: str | None = None
    error_type: str | None = None
    body_truncated: bool = False

    def __post_init__(self) -> None:
        if self.scheme not in _SCHEMES:
            raise ValueError('takeover HTTP scheme must be http or https')
        if self.status is not None and (
            isinstance(self.status, bool) or not isinstance(self.status, int) or not 100 <= self.status <= 599
        ):
            raise ValueError('takeover HTTP status must be between 100 and 599')
        if not isinstance(self.body_truncated, bool):
            raise ValueError('takeover body_truncated must be a boolean')
        object.__setattr__(self, 'location', _optional_text(self.location, 'redirect location', limit=2048))
        object.__setattr__(self, 'error_type', _optional_text(self.error_type, 'HTTP error type'))
        if self.status is None and self.error_type is None:
            raise ValueError('takeover HTTP outcomes require a response status or error type')
        if self.body_truncated and self.error_type is None:
            raise ValueError('truncated takeover HTTP outcomes require an error type')

    @classmethod
    def from_record(cls, record: object) -> Self:
        if not isinstance(record, dict) or set(record) - {
            'scheme',
            'status',
            'location',
            'error_type',
            'body_truncated',
        }:
            raise ValueError('takeover HTTP evidence contains unsupported fields')
        return cls(
            scheme=cast('HttpScheme', _required_text(record.get('scheme'), 'HTTP scheme')),
            status=record.get('status') if record.get('status') is not None else None,
            location=_optional_text(record.get('location'), 'redirect location', limit=2048),
            error_type=_optional_text(record.get('error_type'), 'HTTP error type'),
            body_truncated=record.get('body_truncated', False),
        )

    def to_record(self) -> dict[str, object]:
        record: dict[str, object] = {'scheme': self.scheme}
        if self.status is not None:
            record['status'] = self.status
        if self.location is not None:
            record['location'] = self.location
        if self.error_type is not None:
            record['error_type'] = self.error_type
        if self.body_truncated:
            record['body_truncated'] = True
        return record

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.scheme,
            self.status if self.status is not None else 0,
            self.location or '',
            self.error_type or '',
            self.body_truncated,
        )


@dataclass(frozen=True, slots=True)
class TakeoverIndicator:
    """One provider rule matched by the evidence for a candidate hostname."""

    classification: TakeoverClassification
    service: str
    rule_id: str
    rule_revision: str
    matched: tuple[str, ...]
    scheme: HttpScheme | None = None

    def __post_init__(self) -> None:
        if self.classification not in _CLASSIFICATIONS:
            raise ValueError('takeover classification is not supported')
        if not self.matched or self.matched != tuple(sorted(set(self.matched))):
            raise ValueError('takeover matched predicates must be non-empty, deduplicated, and sorted')
        object.__setattr__(self, 'service', _required_text(self.service, 'service'))
        object.__setattr__(self, 'rule_id', _required_text(self.rule_id, 'rule ID'))
        object.__setattr__(self, 'rule_revision', _required_text(self.rule_revision, 'rule revision'))
        if self.scheme is not None and self.scheme not in _SCHEMES:
            raise ValueError('takeover indicator scheme must be http or https')
        for predicate in self.matched:
            _required_text(predicate, 'matched predicate', limit=512)
        dns_predicates = [predicate.startswith('dns:') for predicate in self.matched]
        if any(dns_predicates) and not all(dns_predicates):
            raise ValueError('takeover indicators cannot mix DNS and HTTP predicates')
        dns_only = all(dns_predicates)
        if dns_only and self.scheme is not None:
            raise ValueError('DNS-only takeover indicators cannot identify an HTTP scheme')
        if not dns_only and self.scheme is None:
            raise ValueError('HTTP takeover indicators must identify the matching scheme')
        if dns_only:
            rcodes = [predicate.removeprefix('dns:terminal-rcode=') for predicate in self.matched]
            if any(rcode not in _RCODES for rcode in rcodes):
                raise ValueError('DNS takeover indicators require canonical terminal RCODE predicates')
        else:
            allowed_prefixes = ('status:', 'body:', 'body-regex:', 'header:')
            if any(not predicate.startswith(allowed_prefixes) for predicate in self.matched):
                raise ValueError('HTTP takeover indicators contain an unsupported predicate')
            for predicate in self.matched:
                if not predicate.startswith('status:'):
                    continue
                raw_status = predicate.removeprefix('status:')
                if not raw_status.isdigit() or not 100 <= int(raw_status) <= 599:
                    raise ValueError('HTTP takeover indicators contain an invalid status predicate')

    @classmethod
    def from_record(cls, record: object) -> Self:
        if not isinstance(record, dict) or set(record) - {
            'classification',
            'service',
            'rule_id',
            'rule_revision',
            'scheme',
            'matched',
        }:
            raise ValueError('takeover indicator must use the canonical fields')
        if not {'classification', 'service', 'rule_id', 'rule_revision', 'matched'} <= set(record):
            raise ValueError('takeover indicator must use the canonical fields')
        raw_matched = record.get('matched')
        if not isinstance(raw_matched, list) or any(not isinstance(item, str) for item in raw_matched):
            raise ValueError('takeover matched predicates must be an array of strings')
        return cls(
            classification=cast(
                'TakeoverClassification',
                _required_text(record.get('classification'), 'classification'),
            ),
            service=_required_text(record.get('service'), 'service'),
            rule_id=_required_text(record.get('rule_id'), 'rule ID'),
            rule_revision=_required_text(record.get('rule_revision'), 'rule revision'),
            scheme=(cast('HttpScheme', _required_text(record.get('scheme'), 'HTTP scheme')) if 'scheme' in record else None),
            matched=tuple(raw_matched),
        )

    def sort_key(self) -> tuple[str, str, str, str]:
        return self.rule_id, self.service, self.classification, self.scheme or ''

    def to_record(self) -> dict[str, object]:
        record: dict[str, object] = {
            'classification': self.classification,
            'service': self.service,
            'rule_id': self.rule_id,
            'rule_revision': self.rule_revision,
            'matched': list(self.matched),
        }
        if self.scheme is not None:
            record['scheme'] = self.scheme
        return record


@dataclass(frozen=True, slots=True)
class TakeoverCandidateOutcome:
    """Complete or explicitly inconclusive takeover evaluation for one hostname."""

    hostname: str
    status: TakeoverCandidateStatus
    dns: tuple[TakeoverDNSOutcome, ...]
    wildcard_dns: tuple[TakeoverDNSOutcome, ...] = ()
    http: tuple[TakeoverHTTPOutcome, ...] = ()
    indicators: tuple[TakeoverIndicator, ...] = ()
    error_types: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        canonical_hostname = normalize_hostname(self.hostname)
        if canonical_hostname != self.hostname:
            raise ValueError('takeover hostname must be canonical')
        if self.status not in _STATUSES:
            raise ValueError('takeover candidate status is not supported')
        if not self.dns or self.dns != tuple(sorted(set(self.dns), key=TakeoverDNSOutcome.sort_key)):
            raise ValueError('takeover candidate DNS evidence must be non-empty, deduplicated, and sorted')
        if len({outcome.resolver for outcome in self.dns}) != len(self.dns):
            raise ValueError('takeover candidate must contain one DNS outcome per resolver')
        if self.wildcard_dns != tuple(sorted(set(self.wildcard_dns), key=TakeoverDNSOutcome.sort_key)):
            raise ValueError('takeover wildcard DNS evidence must be deduplicated and sorted')
        if len({outcome.resolver for outcome in self.wildcard_dns}) != len(self.wildcard_dns):
            raise ValueError('takeover candidate must contain one wildcard DNS outcome per resolver')
        if self.http != tuple(sorted(set(self.http), key=TakeoverHTTPOutcome.sort_key)):
            raise ValueError('takeover HTTP evidence must be deduplicated and sorted')
        if len({outcome.scheme for outcome in self.http}) != len(self.http):
            raise ValueError('takeover candidate must contain one HTTP outcome per scheme')
        if self.indicators != tuple(sorted(set(self.indicators), key=TakeoverIndicator.sort_key)):
            raise ValueError('takeover indicators must be deduplicated and sorted')
        rule_ids = [indicator.rule_id for indicator in self.indicators]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError('takeover candidate cannot contain conflicting observations for one rule')
        if self.error_types != tuple(sorted(set(self.error_types))):
            raise ValueError('takeover candidate errors must be deduplicated and sorted')
        for error_type in self.error_types:
            _required_text(error_type, 'candidate error type')
        nested_errors = {outcome.error_type for outcome in self.dns if outcome.error_type is not None}
        nested_errors.update(outcome.error_type for outcome in self.wildcard_dns if outcome.error_type is not None)
        nested_errors.update(outcome.error_type for outcome in self.http if outcome.error_type is not None)
        if not nested_errors <= set(self.error_types):
            raise ValueError('takeover candidate errors must include every DNS and HTTP outcome error')
        if self.status == 'indicator' and not self.indicators:
            raise ValueError('takeover indicator status requires at least one indicator')
        if self.status != 'indicator' and self.indicators:
            raise ValueError('only takeover indicator status can contain indicators')
        if self.status == 'no-indicator' and self.error_types:
            raise ValueError('complete no-indicator outcomes cannot contain errors')
        if self.status == 'inconclusive' and not self.error_types:
            raise ValueError('inconclusive takeover outcomes require an error type')
        dns_by_resolver = {outcome.resolver: outcome for outcome in self.dns}
        wildcard_by_resolver = {outcome.resolver: outcome for outcome in self.wildcard_dns}
        if (self.indicators or self.http) and (
            any(outcome.error_type is not None for outcome in self.dns)
            or any(outcome.error_type is not None for outcome in self.wildcard_dns)
        ):
            raise ValueError('takeover HTTP evaluation requires error-free candidate and wildcard DNS evidence')
        if self.indicators or self.http:
            if set(wildcard_by_resolver) != set(dns_by_resolver):
                raise ValueError('takeover HTTP evaluation requires one wildcard control per resolver')
            if len({(outcome.cname_chain, outcome.terminal_rcode) for outcome in self.dns}) != 1:
                raise ValueError('takeover HTTP evaluation requires candidate DNS agreement across resolvers')
            if len({(outcome.cname_chain, outcome.terminal_rcode) for outcome in self.wildcard_dns}) != 1:
                raise ValueError('takeover HTTP evaluation requires wildcard DNS agreement across resolvers')
            if any(
                dns_by_resolver[resolver].cname_chain == wildcard.cname_chain
                and dns_by_resolver[resolver].terminal_rcode == wildcard.terminal_rcode
                for resolver, wildcard in wildcard_by_resolver.items()
            ):
                raise ValueError('takeover HTTP evaluation requires resolver-distinct wildcard controls')
        for indicator in self.indicators:
            if indicator.scheme is None:
                matched_rcodes = {
                    predicate.removeprefix('dns:terminal-rcode=')
                    for predicate in indicator.matched
                    if predicate.startswith('dns:terminal-rcode=')
                }
                if len(matched_rcodes) != len(indicator.matched) or not matched_rcodes <= _RCODES:
                    raise ValueError('DNS takeover indicators require canonical terminal RCODE predicates')
                if any(outcome.terminal_rcode not in matched_rcodes or outcome.error_type for outcome in self.dns):
                    raise ValueError('DNS takeover indicators must agree with every resolver outcome')
            else:
                matching_http = [outcome for outcome in self.http if outcome.scheme == indicator.scheme]
                if (
                    len(matching_http) != 1
                    or matching_http[0].status is None
                    or matching_http[0].error_type is not None
                    or matching_http[0].body_truncated
                ):
                    raise ValueError('HTTP takeover indicators require one successful outcome for their matching scheme')
                matched_statuses = {
                    int(predicate.removeprefix('status:'))
                    for predicate in indicator.matched
                    if predicate.startswith('status:') and predicate.removeprefix('status:').isdigit()
                }
                if matched_statuses and matching_http[0].status not in matched_statuses:
                    raise ValueError('HTTP takeover status predicates must agree with their matching outcome')

    @classmethod
    def from_record(cls, hostname: str, details: object) -> Self:
        if not isinstance(details, dict) or set(details) != {
            'status',
            'dns',
            'wildcard_dns',
            'http',
            'indicators',
            'error_types',
        }:
            raise ValueError('takeover details must use the canonical candidate fields')
        raw_dns = details.get('dns')
        raw_wildcard_dns = details.get('wildcard_dns')
        raw_http = details.get('http')
        raw_indicators = details.get('indicators')
        raw_errors = details.get('error_types')
        if (
            not isinstance(raw_dns, list)
            or not isinstance(raw_wildcard_dns, list)
            or not isinstance(raw_http, list)
            or not isinstance(raw_indicators, list)
            or not isinstance(raw_errors, list)
        ):
            raise ValueError('takeover detail collections must be arrays')
        if any(not isinstance(item, str) for item in raw_errors):
            raise ValueError('takeover candidate errors must be an array of strings')
        return cls(
            hostname=normalize_hostname(hostname),
            status=cast('TakeoverCandidateStatus', _required_text(details.get('status'), 'candidate status')),
            dns=tuple(sorted({TakeoverDNSOutcome.from_record(item) for item in raw_dns}, key=TakeoverDNSOutcome.sort_key)),
            wildcard_dns=tuple(
                sorted(
                    {TakeoverDNSOutcome.from_record(item) for item in raw_wildcard_dns},
                    key=TakeoverDNSOutcome.sort_key,
                )
            ),
            http=tuple(sorted({TakeoverHTTPOutcome.from_record(item) for item in raw_http}, key=TakeoverHTTPOutcome.sort_key)),
            indicators=tuple(
                sorted({TakeoverIndicator.from_record(item) for item in raw_indicators}, key=TakeoverIndicator.sort_key)
            ),
            error_types=tuple(sorted(set(raw_errors))),
        )

    def sort_key(self) -> str:
        return self.hostname

    def to_details(self) -> dict[str, object]:
        return {
            'status': self.status,
            'dns': [item.to_record() for item in self.dns],
            'wildcard_dns': [item.to_record() for item in self.wildcard_dns],
            'http': [item.to_record() for item in self.http],
            'indicators': [item.to_record() for item in self.indicators],
            'error_types': list(self.error_types),
        }


def canonical_takeover_outcomes(
    outcomes: list[TakeoverCandidateOutcome] | tuple[TakeoverCandidateOutcome, ...],
) -> tuple[TakeoverCandidateOutcome, ...]:
    by_hostname: dict[str, TakeoverCandidateOutcome] = {}
    for outcome in outcomes:
        existing = by_hostname.get(outcome.hostname)
        if existing is not None and existing != outcome:
            raise ValueError(f'conflicting takeover outcomes for {outcome.hostname}')
        by_hostname[outcome.hostname] = outcome
    return tuple(sorted(by_hostname.values(), key=TakeoverCandidateOutcome.sort_key))


def parse_takeover_details(hostname: str, details: object) -> TakeoverCandidateOutcome:
    outcome = TakeoverCandidateOutcome.from_record(hostname, details)
    if outcome.to_details() != details:
        raise ValueError('takeover details must use canonical structured evidence')
    return outcome
