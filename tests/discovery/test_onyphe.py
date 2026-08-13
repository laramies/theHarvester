import asyncio
import logging
from typing import Any

import pytest

from theHarvester.discovery import onyphe
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_process_keeps_only_canonical_individual_ips_and_preserves_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    monkeypatch.setattr(onyphe.Core, 'get_user_agent', lambda: 'test-agent')
    captured: dict[str, Any] = {}

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        assert urls == ['https://www.onyphe.io/api/v2/search/?q=domain:example.com']
        captured.update(kwargs)
        return [
            FetcherResponse(
                body={
                    'text': 'Success',
                    'results': [
                        {
                            'ip': '192.0.2.10',
                            'alternativeip': ['2001:0db8::10'],
                            'subnet': '192.0.2.0/24',
                            'url': ['https://www.example.com/path'],
                            'asn': 'AS64496',
                            'organization': 'Example Physical Network',
                            'geolocus': {
                                'asn': 'AS64497',
                                'organization': 'Example Logical Network',
                                'subnet': '198.51.100.0/24',
                                'domain': ['geo.example.com'],
                            },
                            'hostname': ['api.example.com'],
                        }
                    ],
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = onyphe.SearchOnyphe('example.com')

    await search.process(proxy=True)

    assert captured['proxy'] is True
    assert captured['json'] is True
    assert captured['include_metadata'] is True
    assert captured['headers']['Authorization'] == 'bearer test-key'
    assert await search.get_ips() == {'192.0.2.10', '2001:db8::10'}
    assert await search.get_hostnames() == {'api.example.com', 'geo.example.com', 'www.example.com'}
    assert await search.get_asns() == {'AS64496', 'AS64497'}
    assert {
        (
            observation.asn,
            observation.organization_label,
            observation.subject_kind,
            observation.subject_value,
        )
        for observation in await search.get_asn_attributions()
    } == {
        (asn, organization, subject_kind, subject_value)
        for asn, organization in {
            ('AS64496', 'Example Physical Network'),
            ('AS64497', 'Example Logical Network'),
        }
        for subject_kind, subject_value in {('ip', '192.0.2.10')}
    }
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.asyncio
async def test_valid_empty_response_is_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'text': 'Success', 'results': []}, status=200, headers={})]

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = onyphe.SearchOnyphe('example.com')

    await search.process()

    assert await search.get_ips() == set()
    assert await search.get_hostnames() == set()
    assert await search.get_asns() == set()
    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


@pytest.mark.parametrize(
    ('response', 'execution_status', 'stop_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse(body={}, status=401, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=403, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=429, headers={}), 'rate-limited', 'http-429'),
        (FetcherResponse(body={}, status=503, headers={}), 'failed', 'http-503'),
        (FetcherResponse(body=['provider-secret-payload'], status=200, headers={}), 'failed', 'invalid-response'),
        (
            FetcherResponse(body={'text': 'Success', 'results': {}}, status=200, headers={}),
            'failed',
            'invalid-response',
        ),
    ],
)
@pytest.mark.asyncio
async def test_failed_responses_are_attributed(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    execution_status: str,
    stop_reason: str,
) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse | None]:
        return [response]

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = onyphe.SearchOnyphe('example.com')

    await search.process()

    assert await search.get_ips() == set()
    assert search.execution_status == execution_status
    assert search.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_malformed_items_preserve_valid_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={
                    'text': 'Success',
                    'results': [
                        {'ip': '192.0.2.10', 'alternativeip': ['not-an-ip', None]},
                        'malformed-record',
                    ],
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = onyphe.SearchOnyphe('example.com')

    await search.process()

    assert await search.get_ips() == {'192.0.2.10'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_malformed_url_preserves_valid_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={
                    'text': 'Success',
                    'results': [{'ip': '192.0.2.10', 'url': ['http://[malformed']}],
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = onyphe.SearchOnyphe('example.com')

    await search.process()

    assert await search.get_ips() == {'192.0.2.10'}
    assert search.execution_status == 'partial'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_failed_response_body_is_not_logged(monkeypatch, caplog) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    monkeypatch.setattr(onyphe.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_fetch_all(*args, **kwargs):
        return [
            FetcherResponse(
                body={'text': 'Failed', 'secret': 'provider-secret-payload'},
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)
    caplog.set_level(logging.INFO, logger=onyphe.__name__)

    search = onyphe.SearchOnyphe('example.com')
    await search.process()

    assert 'provider-secret-payload' not in caplog.text
    assert 'did not succeed' in caplog.text
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'provider-error'


@pytest.mark.asyncio
async def test_unexpected_response_body_is_not_logged(monkeypatch, caplog) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    monkeypatch.setattr(onyphe.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_fetch_all(*args, **kwargs):
        return [FetcherResponse(body='provider-secret-payload', status=200, headers={})]

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)
    caplog.set_level(logging.INFO, logger=onyphe.__name__)
    search = onyphe.SearchOnyphe('example.com')

    await search.process()

    assert 'provider-secret-payload' not in caplog.text
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)

    with pytest.raises(asyncio.CancelledError):
        await onyphe.SearchOnyphe('example.com').process()
