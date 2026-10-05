from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import otilabs
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_catalog import ActivityClass, activity_classes_for_selection, get_source_spec, resolve_sources

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class ProviderSession:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}
        self.exited = False


@pytest.fixture(autouse=True)
def provider_session(monkeypatch: pytest.MonkeyPatch) -> ProviderSession:
    session = ProviderSession()

    @contextlib.asynccontextmanager
    async def fake_open_session(**kwargs: Any) -> AsyncIterator[object]:
        session.kwargs = kwargs
        try:
            yield session
        finally:
            session.exited = True

    monkeypatch.setattr(otilabs.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(otilabs.Core, 'otilabs_key', staticmethod(lambda: 'test-key'))
    return session


def respond(monkeypatch: pytest.MonkeyPatch, response: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def fake_fetch(**kwargs: Any) -> Any:
        calls.append(kwargs)
        return response

    monkeypatch.setattr(otilabs.AsyncFetcher, 'fetch', fake_fetch)
    return calls


def body(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        'count': 4,
        'live_count': 2,
        'returned': 4,
        'subdomains': ['WWW.Example.COM.', 'api.example.com', 'old.example.com', 'cdn.outside.test'],
        'live': [
            {'host': 'www.example.com', 'ip': '192.0.2.10'},
            {'host': 'api.example.com', 'ip': 'edge.provider.test'},
        ],
        'pools': [],
        'sources_used': ['certspotter: 3 found', 'dns-brute: 1 found'],
    }
    payload.update(overrides)
    return payload


@pytest.mark.provider_contract('otilabs')
@pytest.mark.asyncio
async def test_scoped_hosts_and_live_addresses_are_returned(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
) -> None:
    calls = respond(monkeypatch, FetcherResponse(body(), 200, {}))
    search = otilabs.SearchOTILabs('example.com')
    report = await search.process(proxy=True)

    assert report is None
    assert await search.get_hostnames() == {'www.example.com', 'api.example.com', 'old.example.com'}
    assert await search.get_ips() == {'192.0.2.10'}
    assert [call['url'] for call in calls] == ['https://domain-intelligence-api.p.rapidapi.com/domain/example.com/subdomains']
    assert calls[0]['session'] is provider_session
    assert calls[0]['params'] == {'wait': '1'}
    assert calls[0]['json'] is True and calls[0]['include_metadata'] is True
    assert provider_session.kwargs['headers'] == {
        'X-RapidAPI-Key': 'test-key',
        'X-RapidAPI-Host': 'domain-intelligence-api.p.rapidapi.com',
    }
    assert provider_session.kwargs['proxy'] is True
    assert provider_session.exited is True


@pytest.mark.parametrize('key', [None, '', '  '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(otilabs.Core, 'otilabs_key', staticmethod(lambda: key))
    with pytest.raises(MissingKey):
        otilabs.SearchOTILabs('example.com')


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 403, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
        (FetcherResponse({'subdomains': 'many'}, 200, {}), 'failed', 'invalid-response'),
        (FetcherResponse(body(live='many'), 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_provider_failures_are_truthful(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    respond(monkeypatch, response)
    search = otilabs.SearchOTILabs('example.com')
    report = await search.process()

    assert report is not None
    assert report.status == status
    assert report.stop_reason == reason
    assert provider_session.exited is True


@pytest.mark.asyncio
async def test_transport_exception_closes_the_session(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
) -> None:
    async def failing_fetch(**_kwargs: Any) -> Any:
        raise RuntimeError('connection reset')

    monkeypatch.setattr(otilabs.AsyncFetcher, 'fetch', failing_fetch)
    search = otilabs.SearchOTILabs('example.com')
    report = await search.process()

    assert report is not None
    assert (report.status, report.stop_reason) == ('failed', 'transport-error')
    assert provider_session.exited is True


@pytest.mark.asyncio
async def test_malformed_items_keep_valid_results(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = body(
        subdomains=['ok.example.com', 7],
        live=[{'host': 'ok.example.com', 'ip': '192.0.2.20'}, 'bad', {'ip': '192.0.2.30'}],
    )
    respond(monkeypatch, FetcherResponse(payload, 200, {}))
    search = otilabs.SearchOTILabs('example.com')
    report = await search.process()

    assert report is not None
    assert (report.status, report.stop_reason) == ('failed', 'invalid-response')
    assert await search.get_hostnames() == {'ok.example.com'}
    assert await search.get_ips() == {'192.0.2.20'}


@pytest.mark.asyncio
async def test_pending_live_check_is_reported_as_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = body(live_count=None, live=[], sources_used=['certspotter: 3 found', 'liveness: enriching'])
    payload.pop('live')
    respond(monkeypatch, FetcherResponse(payload, 200, {}))
    search = otilabs.SearchOTILabs('example.com')
    report = await search.process()

    assert report is not None
    assert (report.status, report.stop_reason) == ('partial', 'enrichment-pending')
    assert await search.get_hostnames() == {'www.example.com', 'api.example.com', 'old.example.com'}
    assert await search.get_ips() == set()


@pytest.mark.asyncio
async def test_capped_list_is_reported_as_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(monkeypatch, FetcherResponse(body(count=2500, returned=4), 200, {}))
    search = otilabs.SearchOTILabs('example.com')
    report = await search.process()

    assert report is not None
    assert (report.status, report.stop_reason) == ('partial', 'result-cap')


@pytest.mark.asyncio
async def test_empty_result_completes_normally(monkeypatch: pytest.MonkeyPatch) -> None:
    respond(monkeypatch, FetcherResponse(body(count=0, live_count=0, returned=0, subdomains=[], live=[]), 200, {}))
    search = otilabs.SearchOTILabs('example.com')
    report = await search.process()

    assert report is None
    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()


def test_source_is_p1_dns_activity_and_runs_only_when_selected() -> None:
    assert get_source_spec('otilabs').activity is ActivityClass.DNS
    assert activity_classes_for_selection(['otilabs']) == (ActivityClass.DNS,)
    assert 'otilabs' not in resolve_sources('all')
    assert resolve_sources('otilabs') == ['otilabs']
    assert resolve_sources('OTILabs') == ['otilabs']
