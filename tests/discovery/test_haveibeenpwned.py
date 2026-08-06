import logging
from typing import Any

import pytest

from theHarvester.discovery import haveibeenpwned
from theHarvester.lib.api import additional_endpoints
from theHarvester.lib.core import FetcherResponse


def test_public_breach_catalog_does_not_require_api_key() -> None:
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    assert 'hibp-api-key' not in search.headers


@pytest.mark.asyncio
async def test_public_breach_catalog_preserves_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        assert urls == ['https://haveibeenpwned.com/api/v3/breaches?domain=example.com']
        assert kwargs['json'] is True
        assert kwargs['include_metadata'] is True
        return [
            FetcherResponse(
                body=[
                    {
                        'Domain': 'example.com',
                        'BreachDate': '2024-01-02',
                        'DataClasses': ['Email addresses', 'Passwords'],
                    }
                ],
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    await search.process()

    assert await search.get_hostnames() == {'example.com'}
    assert await search.get_breach_dates() == {'2024-01-02'}
    assert await search.get_affected_data() == {'Email addresses', 'Passwords'}
    assert await search.get_emails() == set()
    assert await search.get_pastes() == []
    assert await search.get_breach_types() == set()
    assert await search.get_breaches() == [
        {
            'Domain': 'example.com',
            'BreachDate': '2024-01-02',
            'DataClasses': ['Email addresses', 'Passwords'],
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', [[], None, {}, ['not-a-breach']])
async def test_public_breach_catalog_handles_empty_and_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=payload, status=200, headers={})]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    await search.process()

    assert await search.get_breaches() == []
    assert await search.get_hostnames() == set()
    assert await search.get_breach_dates() == set()
    assert await search.get_affected_data() == set()


@pytest.mark.asyncio
async def test_public_breach_catalog_attributes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'error': 'rate limited'}, status=429, headers={})]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = haveibeenpwned.SearchHaveIBeenPwned('example.com')

    with caplog.at_level(logging.INFO, logger=haveibeenpwned.__name__):
        await search.process()

    assert await search.get_breaches() == []
    assert 'HaveIBeenPwned request failed with HTTP 429' in caplog.text


@pytest.mark.asyncio
async def test_breach_rest_handler_does_not_initialize_unrelated_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=[{'Domain': 'example.com'}], status=200, headers={})]

    monkeypatch.setattr(haveibeenpwned.AsyncFetcher, 'fetch_all', fake_fetch_all)

    result = await additional_endpoints.get_breaches(
        additional_endpoints.DomainRequest(domain='example.com'),
        _api_key='local-api-key',
    )

    assert result == {'status': 'success', 'data': [{'Domain': 'example.com'}]}
