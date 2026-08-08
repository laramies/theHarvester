from __future__ import annotations

import ipaddress
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from theHarvester.lib.completed_result import SCHEMA_VERSION as RESULTS_SCHEMA_VERSION
from theHarvester.lib.enumeration import (
    DEFAULT_DNS_RECURSIVE_QUERY_LIMIT,
    DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
    DEFAULT_RESULT_START,
)
from theHarvester.lib.source_catalog import SOURCE_SPECS, ActivityClass

DEFAULT_DNS_RESOLVERS = '1.1.1.1,8.8.8.8,9.9.9.9'


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def default_database_path() -> Path:
    configured = os.getenv('THEHARVESTER_RUN_DB')
    return Path(configured).expanduser() if configured else Path('~/.local/share/theHarvester/runs.sqlite').expanduser()


def _normalize_target(value: str) -> str:
    target = value.strip().rstrip('.').lower()
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
    target: str = Field(description='Authorized domain name or IP address to enumerate.')
    sources: list[str] = Field(
        min_length=1,
        max_length=len(SOURCE_SPECS),
        description=(
            'Discovery source names or source capabilities. Multiple capabilities select the union of matching '
            'sources and do not filter result fields.'
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
    deadline_seconds: int = Field(
        default=1800,
        ge=30,
        le=86_400,
        description='Hard deadline in seconds for the whole run, including every selected source and action.',
    )
    proxies: bool = Field(
        default=False,
        description='Use configured proxies for supported discovery sources and takeover requests.',
    )
    dns_brute: bool = Field(default=False, description='Try wordlist candidates against DNS.')
    dns_lookup: bool = Field(
        default=False,
        description="Perform reverse DNS lookup across each discovered IPv4 address's /24 network.",
    )
    dns_resolve: bool = Field(
        default=False,
        description='Validate discovered hostnames through the three configured resolver addresses.',
    )
    dns_resolvers: list[str] = Field(
        default_factory=lambda: DEFAULT_DNS_RESOLVERS.split(','),
        min_length=3,
        max_length=3,
        description='Exactly three distinct resolver IP addresses used for DNS validation and recursion.',
    )
    dns_recursive_depth: int = Field(
        default=0,
        ge=0,
        description='Maximum recursive label depth. Zero disables recursive DNS discovery.',
    )
    dns_recursive_query_limit: int = Field(
        default=DEFAULT_DNS_RECURSIVE_QUERY_LIMIT,
        gt=0,
        description='Maximum DNS record queries shared across all three resolver vantages.',
    )
    dns_recursive_runtime_seconds: float = Field(
        default=DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
        gt=0,
        allow_inf_nan=False,
        description='Maximum wall-clock seconds spent in recursive DNS discovery.',
    )
    shodan: bool = Field(default=False, description='Enrich discovered hosts with configured Shodan access.')
    screenshot: bool = Field(default=False, description='Capture screenshots of discovered web services.')
    take_over: bool = Field(
        default=False,
        description='Check discovered hosts for takeover indicators, using configured proxies when enabled.',
    )
    api_scan: bool = Field(
        default=False,
        description='Request common API paths directly from the authorized target.',
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
        normalized = [str(ipaddress.ip_address(value.strip())) for value in values]
        if len(set(normalized)) != 3:
            raise ValueError('DNS resolution requires exactly three distinct resolver IPs')
        return normalized


class SourceResponse(BaseModel):
    name: str
    activity: ActivityClass
    credentials: list[str]
    capabilities: list[str]


class NormalizedResult(BaseModel):
    type: str
    value: str
    dns_status: str | None = None


class ScreenshotRecord(BaseModel):
    name: str
    target: str
    url: str


RunStatus = Literal['queued', 'running', 'cancelling', 'cancelled', 'completed', 'failed']
EvidenceStatus = Literal['complete', 'partial', 'failed']
Activity = Literal['P0', 'P1', 'P2']


class ImportedRunRequest(BaseModel):
    filename: str
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
    evidence: dict[str, Any] | None
    results: list[NormalizedResult]
    source_executions: list[dict[str, Any]]
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
EXPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        'description': 'Normalized run results as JSONL.',
        'content': {
            'application/x-ndjson': {
                'schema': {
                    'type': 'string',
                    'description': (f'UTF-8 {RESULTS_SCHEMA_VERSION} JSONL with one summary followed by normalized findings.'),
                }
            },
        },
    }
}
