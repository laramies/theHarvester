#!/usr/bin/env python3
import asyncio
import logging
from typing import Any

import httpx
import pytest

from theHarvester.discovery import otxsearch
from theHarvester.lib.core import Core, FetcherResponse


class TestOtx:
    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.live_network
    def test_api(self, live_test_domain: str) -> None:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{live_test_domain}/passive_dns'
        response = httpx.get(url, headers={'User-Agent': Core.get_user_agent()}, timeout=30)

        assert response.status_code == 200
        assert isinstance(response.json().get('passive_dns'), list)

    @pytest.mark.asyncio
    async def test_search(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
            return [
                FetcherResponse(
                    body={
                        'passive_dns': [
                            {'hostname': 'api.example.com', 'address': '192.0.2.1'},
                            {'hostname': 'api.example.com', 'address': '2001:0db8::1'},
                            {'hostname': 'api.example.com', 'address': '999.0.0.1'},
                            {'hostname': 'www.example.com', 'address': 'NXDOMAIN'},
                            {'hostname': 'www.example.com', 'address': 1234},
                        ]
                    },
                    status=200,
                    headers={},
                )
            ]

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = otxsearch.SearchOtx(TestOtx.domain())
        report = await search.process()
        assert report is None
        assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
        assert await search.get_ips() == {'192.0.2.1', '2001:db8::1'}

    @pytest.mark.asyncio
    @pytest.mark.parametrize('payload', [None, [], {}, {'passive_dns': None}])
    async def test_malformed_results_return_no_evidence(
        self,
        monkeypatch: pytest.MonkeyPatch,
        payload: Any,
    ) -> None:
        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
            return [FetcherResponse(body=payload, status=200, headers={})]

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = otxsearch.SearchOtx(TestOtx.domain())

        report = await search.process()

        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()
        assert report.status == 'failed'
        assert report.stop_reason == 'invalid-response'

    @pytest.mark.asyncio
    async def test_empty_passive_dns_is_a_valid_zero_yield(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
            return [FetcherResponse(body={'passive_dns': []}, status=200, headers={})]

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = otxsearch.SearchOtx(TestOtx.domain())

        report = await search.process()

        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()
        assert report is None

    @pytest.mark.asyncio
    async def test_provider_failures_are_attributed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[Any]:
            raise OSError('provider unavailable')

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', failed_fetch)
        search = otxsearch.SearchOtx(TestOtx.domain())

        with caplog.at_level(logging.INFO, logger=otxsearch.__name__):
            report = await search.process()

        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()
        assert report.status == 'failed'
        assert report.stop_reason == 'transport-error'
        assert 'OTX request failed' in caplog.text

    @pytest.mark.asyncio
    async def test_missing_transport_response_is_attributed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[None]:
            return [None]

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = otxsearch.SearchOtx(TestOtx.domain())

        report = await search.process()

        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()
        assert report.status == 'failed'
        assert report.stop_reason == 'transport-error'

    @pytest.mark.asyncio
    async def test_http_failure_is_attributed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
            return [FetcherResponse(body={'error': 'unavailable'}, status=503, headers={})]

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = otxsearch.SearchOtx(TestOtx.domain())

        report = await search.process()

        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()
        assert report.status == 'failed'
        assert report.stop_reason == 'http-503'

    @pytest.mark.asyncio
    async def test_cancellation_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def cancelled_fetch(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
            raise asyncio.CancelledError

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', cancelled_fetch)
        search = otxsearch.SearchOtx(TestOtx.domain())

        with pytest.raises(asyncio.CancelledError):
            await search.process()

    @pytest.mark.asyncio
    async def test_rate_limit_waits_once_then_returns_evidence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        responses = [
            FetcherResponse(body={'error': 'rate limited'}, status=429, headers={'retry-after': '2'}),
            FetcherResponse(
                body={'passive_dns': [{'hostname': 'api.example.com', 'address': '192.0.2.1'}]},
                status=200,
                headers={},
            ),
        ]
        waits: list[float] = []

        async def fake_fetch_all(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
            assert kwargs['include_metadata'] is True
            return [responses.pop(0)]

        async def fake_sleep(seconds: float) -> None:
            waits.append(seconds)

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        monkeypatch.setattr(otxsearch.asyncio, 'sleep', fake_sleep)
        search = otxsearch.SearchOtx(TestOtx.domain())

        report = await search.process()

        assert report is None
        assert waits == [2]
        assert await search.get_hostnames() == {'api.example.com'}
        assert await search.get_ips() == {'192.0.2.1'}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ('retry_after', 'expected_waits', 'response_count'),
        [
            (None, [5], 2),
            ('invalid', [5], 2),
            ('61', [], 1),
        ],
    )
    async def test_rate_limit_retry_is_bounded(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        retry_after: str | None,
        expected_waits: list[int],
        response_count: int,
    ) -> None:
        headers = {} if retry_after is None else {'retry-after': retry_after}
        responses = [FetcherResponse(body={}, status=429, headers=headers) for _ in range(response_count)]
        waits: list[float] = []

        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
            return [responses.pop(0)]

        async def fake_sleep(seconds: float) -> None:
            waits.append(seconds)

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        monkeypatch.setattr(otxsearch.asyncio, 'sleep', fake_sleep)
        search = otxsearch.SearchOtx(TestOtx.domain())

        with caplog.at_level(logging.INFO, logger=otxsearch.__name__):
            report = await search.process()

        assert responses == []
        assert waits == expected_waits
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()
        assert report.status == 'rate-limited'
        assert report.stop_reason == 'http-429'
        assert 'OTX request failed with HTTP 429' in caplog.text


if __name__ == '__main__':
    pytest.main()


pytestmark = pytest.mark.provider_contract('otx')
