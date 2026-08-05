import json
import logging
from typing import Any

import pytest

from theHarvester.discovery import threatcrowd


_REPORT = {
    'response_code': '1',
    'subdomains': ['api.example.com', 'api.example.com', 'outside.test'],
    'resolutions': [
        {'ip_address': '192.0.2.1'},
        {'ip_address': '2001:0db8::1'},
        {'ip_address': '999.0.0.1'},
        '2001:db8::2',
        'NXDOMAIN',
        {'ip_address': 1234},
        1234,
    ],
}


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', [_REPORT, json.dumps(_REPORT)])
async def test_process_retains_only_valid_ip_addresses(monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[object]:
        return [payload]

    monkeypatch.setattr(threatcrowd.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = threatcrowd.SearchThreatcrowd('example.com')

    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.1', '2001:db8::1', '2001:db8::2'}


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', ['', 'not-json', '[]', '{"subdomains":"wrong-shape"}'])
async def test_process_handles_empty_or_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[str]:
        return [payload]

    monkeypatch.setattr(threatcrowd.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = threatcrowd.SearchThreatcrowd('example.com')

    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()


@pytest.mark.asyncio
async def test_process_attributes_provider_errors(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[dict[str, str]]:
        return [{'response_code': '0'}]

    monkeypatch.setattr(threatcrowd.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = threatcrowd.SearchThreatcrowd('example.com')

    with caplog.at_level(logging.INFO, logger=threatcrowd.__name__):
        await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert 'ThreatCrowd API returned error code' in caplog.text
