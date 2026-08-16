import asyncio
import logging
from typing import Any

import pytest

from theHarvester.discovery import robtex
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.source_catalog import ResultRoute, get_source_spec


def test_robtex_is_an_ip_source() -> None:
    assert get_source_spec('robtex').routes == {ResultRoute.IPS}


@pytest.mark.asyncio
async def test_robtex_does_not_send_domain_to_reverse_ip_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        requested_urls.extend(urls)
        return [
            FetcherResponse(
                body='{"rrname":"api.example.com","rrtype":"A","rrdata":"192.0.2.1"}',
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')
    await search.process()

    assert requested_urls == ['https://freeapi.robtex.com/pdns/forward/example.com']
    assert await search.get_ips() == {'192.0.2.1'}


@pytest.mark.asyncio
async def test_robtex_collects_ipv4_and_ipv6_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body=(
                    '{"rrname":"example.com","rrtype":"A","rrdata":"192.0.2.1"}\n'
                    '{"rrname":"example.com","rrtype":"AAAA","rrdata":"2001:db8::1"}'
                ),
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')

    await search.process()

    assert await search.get_ips() == {'192.0.2.1', '2001:db8::1'}


@pytest.mark.asyncio
@pytest.mark.parametrize('response', [[], ['']])
async def test_robtex_handles_empty_responses(
    monkeypatch: pytest.MonkeyPatch,
    response: list[str],
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=payload, status=200, headers={}) for payload in response]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')

    await search.process()

    assert await search.get_ips() == set()


@pytest.mark.asyncio
async def test_robtex_reports_malformed_response(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body='not-json\n{}\n[]', status=200, headers={})]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_robtex_attributes_provider_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[str]:
        raise OSError('provider unavailable')

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', failed_fetch)
    search = robtex.SearchRobtex('example.com')

    with caplog.at_level(logging.INFO, logger=robtex.__name__):
        await search.process()

    assert await search.get_ips() == set()
    assert 'Robtex API error' in caplog.text
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'transport-error'


@pytest.mark.asyncio
async def test_robtex_attributes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failed_fetch(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body='service unavailable', status=503, headers={})]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', failed_fetch)
    search = robtex.SearchRobtex('example.com')

    with caplog.at_level(logging.INFO, logger=robtex.__name__):
        await search.process()

    assert await search.get_ips() == set()
    assert 'Robtex request failed with HTTP 503' in caplog.text
    assert search.execution_status == 'failed'
    assert search.stop_reason == 'http-503'


@pytest.mark.asyncio
async def test_robtex_attributes_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    async def rate_limited(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body='too many requests', status=429, headers={})]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', rate_limited)
    search = robtex.SearchRobtex('example.com')

    await search.process()

    assert search.execution_status == 'rate-limited'
    assert search.stop_reason == 'http-429'


@pytest.mark.asyncio
async def test_robtex_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    async def cancelled(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        raise asyncio.CancelledError

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', cancelled)
    search = robtex.SearchRobtex('example.com')

    with pytest.raises(asyncio.CancelledError):
        await search.process(proxy=True)


pytestmark = pytest.mark.provider_contract('robtex')
