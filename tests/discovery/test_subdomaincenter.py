import asyncio
import logging
from typing import Any

import pytest

from theHarvester.discovery import subdomaincenter
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport


@pytest.mark.asyncio
async def test_process_preserves_www_hostname(monkeypatch):
    async def fake_fetch_all(urls, **_kwargs):
        return [FetcherResponse(body=['www.example.com'], status=200, headers={})]

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all))
    search = subdomaincenter.SubdomainCenter('example.com')

    report = await search.process()

    assert await search.get_hostnames() == {'www.example.com'}
    assert report is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('payload', 'expected', 'expected_report'),
    [
        (None, set(), SourceExecutionReport('failed', 'invalid-response')),
        ({'unexpected': 'shape'}, set(), SourceExecutionReport('failed', 'invalid-response')),
        ('api.example.com', set(), SourceExecutionReport('failed', 'invalid-response')),
        (['api.example.com', None], {'api.example.com'}, SourceExecutionReport('partial', 'invalid-response')),
        ([], set(), None),
    ],
)
async def test_process_rejects_malformed_results(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
    expected: set[str],
    expected_report: SourceExecutionReport | None,
) -> None:
    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        assert urls == ['https://api.subdomain.center/?domain=example.com']
        return [FetcherResponse(body=payload, status=200, headers={})]

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = subdomaincenter.SubdomainCenter('example.com')

    report = await search.process()

    assert await search.get_hostnames() == expected
    assert report == expected_report


@pytest.mark.asyncio
async def test_process_attributes_provider_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise OSError('provider unavailable')

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', failed_fetch)
    search = subdomaincenter.SubdomainCenter('example.com')

    with caplog.at_level(logging.INFO, logger=subdomaincenter.__name__):
        report = await search.process()

    assert await search.get_hostnames() == set()
    assert 'SubdomainCenter' in caplog.text
    assert report == SourceExecutionReport('failed', 'transport-error')


@pytest.mark.asyncio
async def test_process_attributes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failed_fetch(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body=[], status=429, headers={})]

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', failed_fetch)
    search = subdomaincenter.SubdomainCenter('example.com')

    with caplog.at_level(logging.INFO, logger=subdomaincenter.__name__):
        report = await search.process()

    assert await search.get_hostnames() == set()
    assert 'SubdomainCenter request failed with HTTP 429' in caplog.text
    assert report == SourceExecutionReport('rate-limited', 'http-429')


@pytest.mark.asyncio
async def test_process_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    async def cancelled(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', cancelled)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await subdomaincenter.SubdomainCenter('example.com').process(proxy=True)


pytestmark = pytest.mark.provider_contract('subdomaincenter')
