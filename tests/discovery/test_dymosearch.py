import asyncio
from typing import Any

import pytest

from theHarvester.discovery import dymosearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.provider_contract('dymo')
@pytest.mark.asyncio
async def test_process_extracts_scoped_canonical_and_suggested_domains(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dymosearch.Core, 'dymo_key', lambda: 'token-xyz')
    captured: dict[str, Any] = {}

    async def fake_post_fetch(url: str, **kwargs: Any) -> FetcherResponse:
        captured.update({'url': url, **kwargs})
        return FetcherResponse(
            {
                'domain': {'domain': 'example.com', 'didYouMean': 'www.example.com'},
                'url': {'domain': 'outside.test', 'didYouMean': 'notexample.com'},
            },
            200,
            {},
        )

    monkeypatch.setattr(dymosearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = dymosearch.SearchDymo('example.com')
    await search.process(proxy=True)

    assert await search.get_hostnames() == {'example.com', 'www.example.com'}
    assert (await search.get_results())['domain']['domain'] == 'example.com'
    assert captured['url'] == dymosearch.SearchDymo.VERIFY_URL
    assert captured['json_body'] == {'domain': 'example.com', 'url': 'https://example.com'}
    assert captured['include_metadata'] is True
    assert captured['proxy'] is True
    assert search.execution_status == 'completed'
    assert search.stop_reason is None


@pytest.mark.parametrize('key', [None, '', '   '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(dymosearch.Core, 'dymo_key', lambda: key)
    with pytest.raises(MissingKey):
        dymosearch.SearchDymo('example.com')


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
        (FetcherResponse({'domain': []}, 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_failures_are_structured(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(dymosearch.Core, 'dymo_key', lambda: 'token')

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(dymosearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = dymosearch.SearchDymo('example.com')
    await search.process()

    assert search.execution_status == status
    assert search.stop_reason == reason


@pytest.mark.asyncio
async def test_empty_object_is_completed_without_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dymosearch.Core, 'dymo_key', lambda: 'token')

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse({}, 200, {})

    monkeypatch.setattr(dymosearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = dymosearch.SearchDymo('example.com')
    await search.process()

    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


@pytest.mark.asyncio
async def test_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dymosearch.Core, 'dymo_key', lambda: 'token')

    async def fake_post_fetch(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(dymosearch.AsyncFetcher, 'post_fetch', fake_post_fetch)
    with pytest.raises(asyncio.CancelledError):
        await dymosearch.SearchDymo('example.com').process()
