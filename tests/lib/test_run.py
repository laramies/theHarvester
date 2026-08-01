from __future__ import annotations

import pytest

from theHarvester.lib.run import (
    LegacyHostnameSource,
    ScopeClass,
    SourceStatus,
    execute_collection,
    legacy_subdomains,
)


class FakeHostnameSearch:
    def __init__(self, values: list[str]) -> None:
        self.values = values
        self.process_calls: list[bool] = []

    async def process(self, proxy: bool = False) -> None:
        self.process_calls.append(proxy)

    async def get_hostnames(self) -> list[str]:
        return self.values


class FailingHostnameSearch:
    async def process(self, proxy: bool = False) -> None:
        raise RuntimeError('provider unavailable')

    async def get_hostnames(self) -> list[str]:
        raise AssertionError('failed sources have no results')


@pytest.mark.asyncio
async def test_collection_normalizes_scope_and_preserves_www_target_behavior() -> None:
    search = FakeHostnameSearch(
        [
            'API.Example.COM.',
            'BÜCHER.Example.COM.',
            'example.com',
            'example.com.attacker.test',
            '',
        ]
    )

    result = await execute_collection(
        'WWW.Example.COM.',
        LegacyHostnameSource(name='fixture', search=search, proxy=True),
    )

    assert result.target == 'example.com'
    assert search.process_calls == [True]
    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.outcome.process_succeeded is True
    assert result.outcome.error_type is None
    assert [(observation.value, observation.scope_class) for observation in result.observations] == [
        ('api.example.com', ScopeClass.IN_SCOPE),
        ('xn--bcher-kva.example.com', ScopeClass.IN_SCOPE),
        ('example.com', ScopeClass.IN_SCOPE),
        ('example.com.attacker.test', ScopeClass.OUT_OF_SCOPE),
    ]
    assert legacy_subdomains(result) == ['api.example.com', 'xn--bcher-kva.example.com']


@pytest.mark.asyncio
async def test_collection_records_a_valid_empty_source() -> None:
    result = await execute_collection(
        'example.com',
        LegacyHostnameSource(name='fixture', search=FakeHostnameSearch([])),
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.outcome.process_succeeded is True
    assert result.outcome.error_type is None
    assert result.observations == ()


@pytest.mark.asyncio
async def test_collection_reports_nonempty_unusable_results_as_failure() -> None:
    result = await execute_collection(
        'example.com',
        LegacyHostnameSource(
            name='fixture',
            search=FakeHostnameSearch(['', '...', 'bad host', 'https://api.example.com']),
        ),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.process_succeeded is True
    assert result.outcome.error_type == 'ValueError'
    assert result.observations == ()


@pytest.mark.asyncio
async def test_collection_records_source_failures_without_results() -> None:
    result = await execute_collection(
        'example.com',
        LegacyHostnameSource(name='fixture', search=FailingHostnameSearch()),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.process_succeeded is False
    assert result.outcome.error_type == 'RuntimeError'
    assert result.observations == ()
