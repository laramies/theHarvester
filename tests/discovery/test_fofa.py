import logging
from typing import Any

import pytest

from theHarvester.discovery import fofa
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_http_failure_is_reported_without_results(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        assert len(urls) == 1
        assert urls[0].startswith('https://fofa.info/api/v1/search/all?')
        assert 'key=test-key' in urls[0]
        assert kwargs['json'] is True
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body={'error': True}, status=429, headers={})]

    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fofa.SearchFofa('example.com')

    with caplog.at_level(logging.INFO, logger=fofa.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert 'Fofa request failed with HTTP 429' in caplog.text


@pytest.mark.parametrize(
    'credentials',
    [('', 'operator@example.com'), ('test-key', '   ')],
)
def test_empty_credentials_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    credentials: tuple[str, str],
) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: credentials)

    with pytest.raises(MissingKey):
        fofa.SearchFofa('example.com')


@pytest.mark.asyncio
async def test_malformed_results_are_reported(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'error': False, 'results': 7}, status=200, headers={})]

    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fofa.SearchFofa('example.com')

    with caplog.at_level(logging.INFO, logger=fofa.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert 'Fofa returned malformed results' in caplog.text


@pytest.mark.asyncio
async def test_success_preserves_scoped_hosts_and_valid_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [
            FetcherResponse(
                body={
                    'error': False,
                    'results': [
                        ['https://API.Example.COM:443', '192.0.2.10'],
                        ['https://outside.test', 'not-an-ip'],
                        ['malformed'],
                    ],
                },
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = fofa.SearchFofa('example.com')

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.10'}
