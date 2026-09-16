import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.lib.source_runner import SourceRequest, run_source


def mock_transport(monkeypatch, responses):
    responses = iter(responses)

    @asynccontextmanager
    async def request(*args, **kwargs):
        body, status, headers = next(responses)
        if isinstance(body, BaseException):
            raise body
        yield SimpleNamespace(
            status=status,
            headers=headers,
            text=AsyncMock(return_value=json.dumps(body)),
            json=AsyncMock(return_value=body),
        )

    monkeypatch.setattr(
        AsyncFetcher,
        '_build_session',
        AsyncMock(return_value=SimpleNamespace(request=request, close=AsyncMock())),
    )
    monkeypatch.setattr(Core, 'dehashed_key', lambda: 'test-key')
    monkeypatch.setattr(Core, 'leaklookup_key', lambda: 'test-key')
    monkeypatch.setattr(Core, 'rocketreach_key', lambda: 'test-key')


@pytest.mark.parametrize('source', ['dehashed', 'leaklookup', 'rocketreach'])
@pytest.mark.parametrize(
    ('body', 'status', 'expected'),
    [
        ({}, 401, ('failed', 'access-denied')),
        ({}, 403, ('failed', 'access-denied')),
        ({}, 429, ('rate-limited', 'http-429')),
        ({}, 503, ('failed', 'http-503')),
        (OSError('transport fixture'), 0, ('failed', 'transport-error')),
        ('malformed response', 200, ('failed', 'invalid-response')),
        ({}, 200, ('failed', 'invalid-response')),
    ],
)
@pytest.mark.asyncio
async def test_post_provider_failure_reaches_source_outcome(monkeypatch, source, body, status, expected):
    mock_transport(monkeypatch, [(body, status, {})])

    outcome = await run_source(SourceRequest(source, 'example.test', 10, 0, False, True))

    assert (outcome.execution.status, outcome.execution.stop_reason) == expected


@pytest.mark.parametrize(
    ('source', 'body'),
    [
        ('dehashed', {'entries': [{'email': 'user@example.test'}]}),
        ('leaklookup', {'error': 'false', 'message': {'Example Breach': [{'email': 'user@example.test'}]}}),
    ],
)
@pytest.mark.asyncio
async def test_post_provider_decodes_http_json_before_collecting_evidence(monkeypatch, source, body):
    mock_transport(monkeypatch, [(body, 200, {})])

    outcome = await run_source(SourceRequest(source, 'example.test', 10, 0, False, True))

    assert outcome.execution.status == 'completed'
    assert [observation.value for observation in outcome.observations if observation.kind == 'email'] == ['user@example.test']


@pytest.mark.parametrize(
    ('source', 'body'),
    [('dehashed', {'entries': []}), ('leaklookup', {'error': 'false', 'message': {}})],
)
@pytest.mark.asyncio
async def test_post_provider_valid_empty_response_stays_complete(monkeypatch, source, body):
    mock_transport(monkeypatch, [(body, 200, {})])

    outcome = await run_source(SourceRequest(source, 'example.test', 10, 0, False, True))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('completed', 'no-results')


@pytest.mark.asyncio
async def test_dehashed_retains_earlier_evidence_when_later_page_fails(monkeypatch):
    mock_transport(monkeypatch, [({'entries': [{'email': 'user@example.test'}] * 100}, 200, {}), ({}, 401, {})])

    outcome = await run_source(SourceRequest('dehashed', 'example.test', 200, 0, False, True))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('partial', 'access-denied')
    assert [observation.value for observation in outcome.observations] == ['user@example.test']


@pytest.mark.asyncio
async def test_dehashed_decodes_the_bounded_retry_response(monkeypatch):
    mock_transport(monkeypatch, [({}, 429, {'retry-after': '0'}), ({'entries': [{'email': 'user@example.test'}]}, 200, {})])

    outcome = await run_source(SourceRequest('dehashed', 'example.test', 10, 0, False, True))

    assert outcome.execution.status == 'completed'
    assert [observation.value for observation in outcome.observations] == ['user@example.test']


@pytest.mark.asyncio
async def test_leaklookup_provider_error_is_not_successful_absence(monkeypatch):
    mock_transport(monkeypatch, [({'error': 'true', 'message': 'provider detail'}, 200, {})])

    outcome = await run_source(SourceRequest('leaklookup', 'example.test', 10, 0, False, True))

    assert (outcome.execution.status, outcome.execution.stop_reason) == ('failed', 'provider-error')


@pytest.mark.parametrize(
    ('source', 'body', 'status'),
    [
        ('dehashed', {'entries': [None]}, 'failed'),
        ('dehashed', {'entries': [None, {'email': 'user@example.test'}]}, 'partial'),
        ('leaklookup', {'message': {'Example Breach': None}}, 'failed'),
        ('leaklookup', {'message': {'Example Breach': [None, {'email': 'user@example.test'}]}}, 'partial'),
    ],
)
@pytest.mark.asyncio
async def test_post_provider_malformed_records_do_not_complete_successfully(monkeypatch, source, body, status):
    mock_transport(monkeypatch, [(body, 200, {})])

    outcome = await run_source(SourceRequest(source, 'example.test', 10, 0, False, True))

    assert (outcome.execution.status, outcome.execution.stop_reason) == (status, 'invalid-response')
    emails = [observation.value for observation in outcome.observations if observation.kind == 'email']
    assert emails == (['user@example.test'] if status == 'partial' else [])
