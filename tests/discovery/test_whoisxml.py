from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import whoisxml
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class ProviderSession:
    def __init__(self) -> None:
        self.exited = False


@pytest.fixture(autouse=True)
def provider_session(monkeypatch: pytest.MonkeyPatch) -> ProviderSession:
    session = ProviderSession()

    @contextlib.asynccontextmanager
    async def fake_open_session(**_kwargs: Any) -> AsyncIterator[object]:
        try:
            yield session
        finally:
            session.exited = True

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'open_session', fake_open_session)
    return session


@pytest.mark.provider_contract('whoisxml')
@pytest.mark.asyncio
async def test_response_body_is_not_logged_and_scoped_records_are_returned(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', staticmethod(lambda: 'test-key'))
    calls: list[dict[str, Any]] = []
    responses = [
        FetcherResponse(
            {
                'secret': 'provider-secret-payload',
                'result': {
                    'count': 2,
                    'nextPageSearchAfter': 'www.example.com',
                    'records': [
                        {'domain': 'API.Example.COM.'},
                        {'domain': 'outside.test'},
                    ],
                },
            },
            200,
            {},
        ),
        FetcherResponse(
            {
                'result': {
                    'count': 1,
                    'nextPageSearchAfter': '',
                    'records': [{'domain': 'www.example.com'}],
                },
            },
            200,
            {},
        ),
    ]

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', fake_fetch)
    search = whoisxml.SearchWhoisXML('example.com', 3)
    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
    assert report is None
    assert [call['url'] for call in calls] == ['https://subdomains.whoisxmlapi.com/api/v2'] * 2
    assert all(call['session'] is provider_session for call in calls)
    assert [call['params'] for call in calls] == [
        {'apiKey': 'test-key', 'domainName': 'example.com'},
        {'apiKey': 'test-key', 'domainName': 'example.com', 'searchAfter': 'www.example.com'},
    ]
    assert all(call['json'] is True and call['include_metadata'] is True for call in calls)
    assert provider_session.exited is True


@pytest.mark.parametrize('key', [None, '', '  '])
def test_missing_or_blank_key_fails_closed(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', staticmethod(lambda: key))
    with pytest.raises(MissingKey):
        whoisxml.SearchWhoisXML('example.com', 10)


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_limit_must_be_positive(monkeypatch: pytest.MonkeyPatch, limit: Any) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', staticmethod(lambda: 'test-key'))
    with pytest.raises(ValueError, match='positive integer'):
        whoisxml.SearchWhoisXML('example.com', limit)


@pytest.mark.parametrize(
    ('response', 'status', 'reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse({}, 401, {}), 'failed', 'access-denied'),
        (FetcherResponse({}, 429, {}), 'rate-limited', 'http-429'),
        (FetcherResponse({}, 503, {}), 'failed', 'http-503'),
        (FetcherResponse([], 200, {}), 'failed', 'invalid-response'),
        (FetcherResponse({'result': {'records': 'many'}}, 200, {}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_provider_failures_are_truthful(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    status: str,
    reason: str,
) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', fake_fetch)
    search = whoisxml.SearchWhoisXML('example.com', 10)
    report = await search.process()

    assert report.status == status
    assert report.stop_reason == reason


@pytest.mark.asyncio
async def test_malformed_rows_preserve_valid_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(
            {
                'result': {
                    'count': 2,
                    'nextPageSearchAfter': '',
                    'records': [{'domain': 'ok.example.com'}, {'domain': 7}],
                }
            },
            200,
            {},
        )

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', fake_fetch)
    search = whoisxml.SearchWhoisXML('example.com', 10)
    report = await search.process()

    assert await search.get_hostnames() == {'ok.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_later_page_failure_preserves_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse(
            {
                'result': {
                    'count': 1,
                    'nextPageSearchAfter': 'next.example.com',
                    'records': [{'domain': 'api.example.com'}],
                }
            },
            200,
            {},
        ),
        FetcherResponse({}, 429, {}),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', fake_fetch)
    search = whoisxml.SearchWhoisXML('example.com', 10)
    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert report.status == 'rate-limited'
    assert report.stop_reason == 'http-429'


@pytest.mark.parametrize(
    ('domains', 'expected_status'),
    [
        (('api.example.com', 'mail.example.com'), 'partial'),
        (('outside.test', 'other.test'), 'failed'),
    ],
)
@pytest.mark.asyncio
async def test_repeated_cursor_status_reflects_retained_evidence(
    monkeypatch: pytest.MonkeyPatch,
    domains: tuple[str, str],
    expected_status: str,
) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', staticmethod(lambda: 'test-key'))
    responses = [
        FetcherResponse(
            {'result': {'nextPageSearchAfter': 'same', 'records': [{'domain': domains[0]}]}},
            200,
            {},
        ),
        FetcherResponse(
            {'result': {'nextPageSearchAfter': 'same', 'records': [{'domain': domains[1]}]}},
            200,
            {},
        ),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', fake_fetch)
    report = await whoisxml.SearchWhoisXML('example.com', 10).process()

    assert report.status == expected_status
    assert report.stop_reason == 'repeated-cursor'


@pytest.mark.asyncio
async def test_cancellation_closes_provider_session(
    monkeypatch: pytest.MonkeyPatch,
    provider_session: ProviderSession,
) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', staticmethod(lambda: 'test-key'))

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await whoisxml.SearchWhoisXML('example.com', 10).process()
    assert provider_session.exited is True
