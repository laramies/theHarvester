from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from theHarvester.lib.completed_result import parse_virtual_host_details
from theHarvester.lib.enumeration import (
    DEFAULT_DNS_RECURSIVE_QUERY_LIMIT,
    DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
    DEFAULT_RESULT_START,
    DEFAULT_SOURCE_WORKERS,
)
from theHarvester.lib.evidence_types import EvidenceStatus  # noqa: TC001 - Pydantic resolves this annotation at runtime
from theHarvester.lib.resolver_selection import DEFAULT_DNS_RESOLVERS, normalize_resolver_addresses
from theHarvester.lib.result_values import normalize_asn
from theHarvester.lib.source_catalog import (
    SOURCE_SPECS,
    ActivityClass,
    hostname_collection_conflicts,
    selected_action_names,
)
from theHarvester.lib.virtual_host import (
    DEFAULT_VHOST_CONCURRENCY,
    DEFAULT_VHOST_REQUEST_LIMIT,
    DEFAULT_VHOST_RUNTIME_SECONDS,
    DEFAULT_VHOST_TIMEOUT_SECONDS,
    VirtualHostLimits,
    VirtualHostRequest,
    normalize_virtual_host_candidates,
    normalize_virtual_host_endpoint,
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_target(value: str) -> str:
    target = value.strip().rstrip('.')
    if target[:2].casefold() == 'as' and target[2:].isascii() and target[2:].isdecimal():
        return normalize_asn(target)
    target = target.lower()
    if not target or len(target) > 253 or any(character in target for character in '/?#@'):
        raise ValueError('Target must be a hostname or IP address')
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        try:
            target = target.encode('idna').decode('ascii')
        except UnicodeError as error:
            raise ValueError('Target must be a valid hostname') from error
        labels = target.split('.')
        if any(
            not label
            or len(label) > 63
            or label.startswith('-')
            or label.endswith('-')
            or not all(character.isalnum() or character == '-' for character in label)
            for label in labels
        ):
            raise ValueError('Target must be a valid hostname')
        return target


class RunRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    target: str = Field(
        description='Authorized domain name or IP address, or an explicit AS-prefixed network pivot for RouteViews.'
    )
    sources: list[str] = Field(
        max_length=len(SOURCE_SPECS),
        description=(
            'Discovery source names or source capabilities. Multiple capabilities select the union of matching '
            'sources and do not filter result fields. May be empty when a target-only action is selected.'
        ),
    )
    limit: int = Field(
        default=500,
        ge=1,
        le=10_000,
        description='Maximum results requested from each source when that provider supports a limit.',
    )
    start: int = Field(
        default=DEFAULT_RESULT_START,
        ge=0,
        description='Starting result offset for providers that support pagination.',
    )
    source_workers: int = Field(
        default=DEFAULT_SOURCE_WORKERS,
        strict=True,
        ge=1,
        description='Maximum discovery sources run concurrently. Every selected source still runs.',
    )
    deadline_seconds: int | None = Field(
        default=None,
        ge=30,
        le=86_400,
        description=(
            'Optional hard deadline for the whole run. Resolution, reverse, and recursive DNS runs default to '
            'unlimited; other runs default to 1800 seconds.'
        ),
    )
    proxies: bool = Field(
        default=False,
        description='Use configured proxies for supported discovery sources and takeover requests.',
    )
    no_hosts: bool = Field(
        default=False,
        description='Exclude hostname results while retaining other result types returned by selected sources.',
    )
    dns_brute: bool = Field(default=False, description='Try wordlist candidates below the authorized target through DNS.')
    dns_lookup: bool = Field(
        default=False,
        description=(
            'Reverse DNS across discovered IPv4 /24 ranges through one deduplicated job set capped at 20 active '
            'PTR jobs. Query and runtime limits are unlimited by default.'
        ),
    )
    dns_resolve: bool = Field(
        default=False,
        description=(
            'Validate deduplicated discovered hostnames once per A, AAAA, and CNAME record through one run-wide '
            'phase capped at 20 active hostname jobs. Query and runtime limits are unlimited by default.'
        ),
    )
    dns_resolvers: list[str] = Field(
        default_factory=lambda: list(DEFAULT_DNS_RESOLVERS),
        min_length=1,
        description=('Distinct resolver IPv4 or IPv6 addresses used by DNS actions. Recursive DNS requires exactly three.'),
    )
    dns_recursive_depth: int = Field(
        default=0,
        ge=0,
        description='Maximum recursive label depth. Zero disables recursive DNS discovery.',
    )
    dns_recursive_query_limit: int | None = Field(
        default=DEFAULT_DNS_RECURSIVE_QUERY_LIMIT,
        gt=0,
        description='Maximum DNS record queries shared across all three resolver vantages.',
    )
    dns_recursive_runtime_seconds: float | None = Field(
        default=DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
        gt=0,
        allow_inf_nan=False,
        description='Maximum wall-clock seconds spent in recursive DNS discovery.',
    )
    routeviews: bool = Field(
        default=False,
        description=(
            'Enrich discovered IPs with sourced ASN attribution, or an explicitly targeted ASN or IP address, through '
            'RouteViews. Returned routing relationships do not establish ownership, authorization, or target scope.'
        ),
    )
    shodan: bool = Field(default=False, description='Enrich discovered hosts with configured Shodan access.')
    screenshot: bool = Field(
        default=False,
        description='Capture discovered web services, or the authorized target when no discovery sources are selected.',
    )
    takeover: bool = Field(
        default=False,
        description='Check discovered hosts for takeover indicators, using configured proxies when enabled.',
    )
    api_scan: bool = Field(
        default=False,
        description='Request common API paths directly from the authorized target.',
    )
    api_scan_paths: list[str] = Field(
        default_factory=list,
        max_length=500,
        description='Optional endpoint paths used by API scan instead of its bundled wordlist.',
    )
    vhost: bool = Field(
        default=False,
        description='Test harvested in-scope hostnames against harvested literal IPs within one shared cap.',
    )
    vhost_endpoint: str = Field(
        default='',
        description='Optional literal-IP HTTP or HTTPS endpoint; providing one also enables virtual-host discovery.',
    )
    vhost_candidates: list[str] = Field(
        default_factory=list,
        max_length=1000,
        description='Optional in-scope hostnames added to harvested candidates; providing one also enables discovery.',
    )
    vhost_request_limit: int = Field(
        default=DEFAULT_VHOST_REQUEST_LIMIT,
        ge=5,
        le=10_000,
        description='Hard request cap shared by virtual-host context, controls, candidates, and confirmations.',
    )
    vhost_runtime_seconds: float = Field(
        default=DEFAULT_VHOST_RUNTIME_SECONDS,
        gt=0,
        le=3600,
        allow_inf_nan=False,
        description='Hard wall-clock cap for virtual-host discovery.',
    )
    vhost_timeout_seconds: float = Field(
        default=DEFAULT_VHOST_TIMEOUT_SECONDS,
        gt=0,
        le=300,
        allow_inf_nan=False,
        description='Timeout for each virtual-host request.',
    )
    vhost_concurrency: int = Field(
        default=DEFAULT_VHOST_CONCURRENCY,
        ge=1,
        le=100,
        description='Maximum concurrent virtual-host candidate requests.',
    )
    vhost_insecure: bool = Field(
        default=False,
        description='Disable certificate verification for virtual-host HTTPS probes and retain that fact in evidence.',
    )

    @field_validator('target')
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return _normalize_target(value)

    @field_validator('sources')
    @classmethod
    def validate_sources(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError('Sources must not contain duplicates')
        return values

    @field_validator('dns_resolvers')
    @classmethod
    def validate_dns_resolvers(cls, values: list[str]) -> list[str]:
        return normalize_resolver_addresses(values)

    @field_validator('api_scan_paths')
    @classmethod
    def validate_api_scan_paths(cls, values: list[str]) -> list[str]:
        paths = [value.strip() for value in values]
        if any(
            not path
            or not path.startswith('/')
            or len(path) > 2048
            or '://' in path
            or any(character in path for character in '\r\n')
            for path in paths
        ):
            raise ValueError('API scan paths must be non-empty URL paths beginning with /')
        if len(paths) != len(set(paths)):
            raise ValueError('API scan paths must not contain duplicates')
        return paths

    @model_validator(mode='after')
    def validate_hostname_collection(self) -> Self:
        if conflicts := hostname_collection_conflicts(self.model_dump()):
            raise ValueError(f'--no-hosts cannot be combined with: {", ".join(conflicts)}')
        return self

    @model_validator(mode='after')
    def validate_virtual_host_request(self) -> Self:
        has_endpoint = bool(self.vhost_endpoint.strip())
        has_candidates = bool(self.vhost_candidates)
        if not (self.vhost or has_endpoint or has_candidates):
            return self
        try:
            ipaddress.ip_address(self.target)
        except ValueError:
            pass
        else:
            raise ValueError('Virtual-host discovery requires a hostname target scope')
        if self.proxies:
            raise ValueError('Virtual-host discovery supports direct transport only; proxies must be disabled')
        if not self.sources and not (has_endpoint and has_candidates):
            raise ValueError('Virtual-host discovery needs a discovery source unless endpoint and candidates are supplied')
        self.vhost = True
        if has_endpoint:
            self.vhost_endpoint = normalize_virtual_host_endpoint(self.vhost_endpoint)
        if has_candidates:
            self.vhost_candidates = list(normalize_virtual_host_candidates(self.target, tuple(self.vhost_candidates)))
        if has_endpoint and has_candidates:
            VirtualHostRequest(
                endpoint=self.vhost_endpoint,
                scope=self.target,
                candidates=tuple(self.vhost_candidates),
                limits=VirtualHostLimits(
                    request_limit=self.vhost_request_limit,
                    runtime_seconds=self.vhost_runtime_seconds,
                    timeout_seconds=self.vhost_timeout_seconds,
                    concurrency=self.vhost_concurrency,
                ),
                insecure=self.vhost_insecure,
            )
        return self

    @model_validator(mode='after')
    def validate_selected_work(self) -> RunRequest:
        action_names = selected_action_names(self.model_dump())
        if not self.sources and not action_names:
            raise ValueError('Select at least one discovery source or action')
        if self.target.startswith('AS') and self.target[2:].isdecimal():
            if self.sources or action_names != ('routeviews',):
                raise ValueError('ASN target requires RouteViews as the only selected work')
        elif self.routeviews and not self.sources:
            try:
                ipaddress.ip_address(self.target)
            except ValueError as error:
                raise ValueError('RouteViews hostname target requires a discovery source') from error
        if self.dns_recursive_depth > 0 and len(self.dns_resolvers) != 3:
            raise ValueError('Recursive DNS requires exactly three distinct resolver IPs')
        if self.deadline_seconds is None and not (self.dns_resolve or self.dns_lookup or self.dns_recursive_depth > 0):
            self.deadline_seconds = 1800
        return self


class SourceResponse(BaseModel):
    name: str
    activity: ActivityClass
    credentials: list[str]
    ready: bool
    capabilities: list[str]


class ActionResponse(BaseModel):
    name: str
    activity: ActivityClass


class SourceCatalogResponse(BaseModel):
    sources: list[SourceResponse]
    actions: list[ActionResponse]


class DatabaseImportResponse(BaseModel):
    filename: str
    imported_run_ids: list[str]
    skipped_run_ids: list[str]


class VirtualHostObservationResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    endpoint: str
    http_host: str
    tls_server_name: str | None
    classification: Literal['distinct']
    phase: Literal['body']
    status: int
    location: str | None
    body_sha256: str
    body_size: int
    body_truncated: bool
    context_phase: Literal['body']
    context_status: int
    context_location: str | None
    context_body_sha256: str
    context_body_size: int
    context_body_truncated: bool
    control_phase: Literal['body']
    control_status: int
    control_location: str | None
    control_body_sha256: str
    control_body_size: int
    control_body_truncated: bool
    confirmation_body_sha256: str | None
    tls_verified: bool | None
    distinct_signals: list[str]
    reflection_normalized: bool


class PrefixOriginObservationResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    type: Literal['observed-origin']
    action: str
    origin_asn: str
    collected_at: str


class BgpRouteObservationResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    type: Literal['bgp-route']
    action: str
    origin_asn: str
    collector: str
    peer_asn: str
    peer_address: str
    as_path: str
    communities: str
    observed_at: str
    collected_at: str


class RpkiValidationObservationResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    type: Literal['rpki-validation']
    action: str
    origin_asn: str
    state: Literal['valid', 'invalid', 'not-found']
    observed_at: str
    collected_at: str


class AsnAttributionSubjectResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    type: Literal['hostname', 'ip']
    value: str


class AsnAttributionObservationResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    type: Literal['organization-attribution']
    producer_kind: Literal['source', 'action']
    producer: str
    organization_label: str
    subject: AsnAttributionSubjectResponse
    collected_at: str


class ShodanHttpDetailsResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    title: str | None = None
    server: str | None = None
    components: list[str] = Field(default_factory=list)


class ShodanTlsDetailsResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    subject_cn: str | None = None
    subject_alt_names: list[str] = Field(default_factory=list)
    issuer_cn: str | None = None
    expires_at: str | None = None
    sha256: str | None = None
    jarm: str | None = None


class ShodanServiceResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    port: int = Field(ge=1, le=65535)
    transport: Literal['tcp', 'udp']
    product: str | None = None
    version: str | None = None
    observed_at: str | None = None
    cpes: list[str] = Field(default_factory=list)
    http: ShodanHttpDetailsResponse | None = None
    tls: ShodanTlsDetailsResponse | None = None


class ShodanHostDetailsResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    asn: str | None = None
    organization: str | None = None
    isp: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    services: list[ShodanServiceResponse] = Field(min_length=1)


class NormalizedResult(BaseModel):
    model_config = ConfigDict(extra='forbid')

    type: str
    value: str
    sources: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    scope: Literal['external-relationship'] | None = None
    details: ShodanHostDetailsResponse | None = Field(
        default=None,
        description='Canonical host and service evidence for shodan-host results.',
    )
    observations: (
        list[
            VirtualHostObservationResponse
            | PrefixOriginObservationResponse
            | BgpRouteObservationResponse
            | RpkiValidationObservationResponse
            | AsnAttributionObservationResponse
        ]
        | None
    ) = Field(default=None, min_length=1)

    @model_validator(mode='after')
    def validate_result(self) -> Self:
        if self.type == 'vhost':
            raise ValueError('vhost is not a result type; use hostname with virtual-host observations')
        if self.type == 'shodan-host':
            from theHarvester.lib.shodan_evidence import ShodanHostObservation

            if self.scope is not None or self.observations is not None or self.details is None:
                raise ValueError('Shodan host results require details without scope or observations')
            shodan_details = self.details.model_dump(exclude_none=True, exclude_defaults=True)
            shodan_host = ShodanHostObservation.from_record(self.value, shodan_details)
            if shodan_host.ip != self.value or shodan_host.to_details() != shodan_details:
                raise ValueError('Shodan host results must use canonical structured details')
        elif self.type == 'prefix':
            if self.scope != 'external-relationship':
                raise ValueError('Prefix results must have external-relationship scope')
            if self.observations is not None:
                from theHarvester.lib.network_evidence import parse_network_observation_details

                parse_network_observation_details(self.value, [details.model_dump() for details in self.observations])
        elif self.scope is not None:
            raise ValueError('Only prefix results have relationship scope')
        elif self.observations is not None:
            details = [details.model_dump() for details in self.observations]
            if self.type == 'asn':
                from theHarvester.lib.asn_attribution import parse_asn_attribution_details

                parse_asn_attribution_details(self.value, details)
            elif self.type == 'hostname':
                parse_virtual_host_details(self.value, details)
            else:
                raise ValueError('Structured observations belong to ASN, hostname, or prefix results')
        elif self.details is not None:
            raise ValueError('Structured details belong to Shodan host results')
        return self


RunResult = NormalizedResult


class ScreenshotRecord(BaseModel):
    name: str
    target: str
    url: str


RunStatus = Literal['queued', 'running', 'cancelling', 'cancelled', 'completed', 'failed']
Activity = Literal['P0', 'P1', 'P2']


class ImportedRunRequest(BaseModel):
    filename: str
    source_run_id: str
    sources: list[str]
    activities: list[Activity]


class RunSummary(BaseModel):
    run_id: str
    target: str
    status: RunStatus
    origin: Literal['local', 'imported']
    created_at: str
    started_at: str | None
    completed_at: str | None
    cancellation_requested_at: str | None
    error: str | None
    sources: list[str]
    activities: list[Activity]
    evidence_status: EvidenceStatus | None
    result_count: int


class RunDetail(RunSummary):
    request: RunRequest | ImportedRunRequest
    results: list[RunResult]
    source_executions: list[dict[str, Any]]
    action_executions: list[dict[str, Any]]
    artifacts: list[dict[str, Any]]
    screenshots: list[ScreenshotRecord]
    log: str


RUN_REQUEST_OPENAPI = {
    'requestBody': {
        'required': True,
        'content': {'application/json': {'schema': RunRequest.model_json_schema()}},
    }
}
IMPORT_REQUEST_OPENAPI = {
    'requestBody': {
        'required': True,
        'content': {'application/x-ndjson': {'schema': {'type': 'string', 'format': 'binary'}}},
    }
}
DATABASE_IMPORT_REQUEST_OPENAPI = {
    'requestBody': {
        'required': True,
        'content': {'application/vnd.sqlite3': {'schema': {'type': 'string', 'format': 'binary'}}},
    }
}
EXPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        'description': 'Normalized run results as JSONL.',
        'content': {
            'application/x-ndjson': {
                'schema': {
                    'type': 'string',
                    'description': 'UTF-8 JSONL with one summary followed by normalized findings.',
                }
            },
        },
    }
}
