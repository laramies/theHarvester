import logging
from typing import Any

import pytest

from theHarvester.discovery import shodanct
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_process_returns_normalized_in_scope_hostnames(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    requests: list[tuple[list[str], dict[str, Any]]] = []

    async def fake_fetch_all(urls: list[str], **kwargs: Any) -> list[FetcherResponse]:
        requests.append((urls, kwargs))
        return [
            FetcherResponse(
                body=[
                    'API.Example.COM.',
                    '*.wild.example.com',
                    'www.example.com',
                    'example.com',
                    'outside.test',
                    'not valid.example.com',
                    '-bad.example.com',
                    None,
                ],
                status=200,
                headers={},
            )
        ]

    monkeypatch.setattr(shodanct.AsyncFetcher, 'fetch_all', fake_fetch_all)

    with caplog.at_level(logging.INFO, logger=shodanct.__name__):
        search = shodanct.SearchShodanCt(' Example.COM. ')
        await search.process()

    assert await search.get_hostnames() == {
        'api.example.com',
        'example.com',
        'wild.example.com',
        'www.example.com',
    }
    assert requests == [
        (
            ['https://ctl.shodan.io/api/v1/domain/example.com/hostnames'],
            {'json': True, 'proxy': False, 'include_metadata': True},
        )
    ]
    assert 'Shodan CT ignored malformed hostname data' in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [429, 500])
async def test_process_reports_non_success_status(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    status: int,
) -> None:
    async def fake_fetch_all(_urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body={'error': 'unavailable'}, status=status, headers={})]

    monkeypatch.setattr(shodanct.AsyncFetcher, 'fetch_all', fake_fetch_all)

    with caplog.at_level(logging.INFO, logger=shodanct.__name__):
        search = shodanct.SearchShodanCt('example.com')
        await search.process()

    assert await search.get_hostnames() == set()
    assert f'Shodan CT request failed with HTTP {status}' in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'message'),
    [
        (None, 'Shodan CT request failed'),
        (FetcherResponse(body='not a list', status=200, headers={}), 'Shodan CT returned malformed data'),
    ],
)
async def test_process_reports_transport_and_malformed_responses(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    response: FetcherResponse | None,
    message: str,
) -> None:
    async def fake_fetch_all(_urls: list[str], **_kwargs: Any) -> list[FetcherResponse | None]:
        return [response]

    monkeypatch.setattr(shodanct.AsyncFetcher, 'fetch_all', fake_fetch_all)

    with caplog.at_level(logging.INFO, logger=shodanct.__name__):
        search = shodanct.SearchShodanCt('example.com')
        await search.process()

    assert await search.get_hostnames() == set()
    assert message in caplog.text


pytestmark = pytest.mark.provider_contract('shodanct')
