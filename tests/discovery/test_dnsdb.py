from __future__ import annotations

import logging

import pytest

from theHarvester.discovery import dnsdb
from theHarvester.discovery.constants import MissingKey


def _install_response(
    monkeypatch: pytest.MonkeyPatch,
    lines: tuple[bytes, ...],
    *,
    status: int = 200,
    stream_error: Exception | None = None,
) -> dict[str, object]:
    requested: dict[str, object] = {}
    lines_left = list(lines)

    class FakeContent:
        def __aiter__(self) -> FakeContent:
            return self

        async def __anext__(self) -> bytes:
            if not lines_left:
                if stream_error is not None:
                    raise stream_error
                raise StopAsyncIteration
            return lines_left.pop(0)

    class FakeResponse:
        def __init__(self) -> None:
            self.status = status

        content = FakeContent()

        async def __aenter__(self) -> FakeResponse:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    class FakeSession:
        def get(self, url: str, **kwargs: object) -> FakeResponse:
            requested['url'] = url
            requested['request'] = kwargs
            return FakeResponse()

        async def __aenter__(self) -> FakeSession:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    async def fake_build_session(
        headers: dict[str, str],
        timeout: object,
        proxy_url: str | None = None,
        proxy_type: str | None = None,
    ) -> FakeSession:
        requested['session'] = {
            'headers': headers,
            'timeout': timeout,
            'proxy_url': proxy_url,
            'proxy_type': proxy_type,
        }
        return FakeSession()

    monkeypatch.setattr(dnsdb.AsyncFetcher, '_build_session', fake_build_session)
    return requested


def test_blank_key_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: '  ')

    with pytest.raises(MissingKey):
        dnsdb.SearchDNSDB('example.com')


@pytest.mark.asyncio
async def test_process_collects_normalized_in_scope_rrset_owners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    requested = _install_response(
        monkeypatch,
        (
            b'{"cond":"begin"}\n',
            b'{"obj":{"rrname":"API.Example.COM.","rrtype":"A"}}\n',
            b'{"obj":{"rrname":"example.com.","rrtype":"NS"}}\n',
            b'{"obj":{"rrname":"*.wild.example.com.","rrtype":"A"}}\n',
            b'{"obj":{"rrname":"outside.test.","rrtype":"A"}}\n',
            b'{"cond":"succeeded"}\n',
        ),
    )

    search = dnsdb.SearchDNSDB(' Example.COM. ')
    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert requested['url'] == 'https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.example.com?limit=0'
    session_options = requested['session']
    assert isinstance(session_options, dict)
    assert session_options['headers'] == {
        'Accept': 'application/x-ndjson',
        'User-Agent': f'theHarvester/{dnsdb.__version__}',
        'X-API-Key': 'dnsdb-test-key',
    }


@pytest.mark.asyncio
async def test_process_uses_configured_proxy_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    monkeypatch.setattr(
        dnsdb.Core,
        'proxy_list',
        lambda: {'http': ['http://proxy.example:8080'], 'socks5': []},
    )
    monkeypatch.setattr(dnsdb.AsyncFetcher, '_proxy_list', None)
    requested = _install_response(
        monkeypatch,
        (
            b'{"cond":"begin"}\n',
            b'{"cond":"succeeded"}\n',
        ),
    )

    await dnsdb.SearchDNSDB('example.com').process(True)

    request_options = requested['request']
    assert isinstance(request_options, dict)
    assert request_options['proxy'] == 'http://proxy.example:8080'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('last_line', 'expected_message'),
    [
        (b'{"cond":"limited"}\n', 'ended with limited'),
        (b'not-json\n', 'malformed NDJSON'),
    ],
)
async def test_process_preserves_partial_results(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    last_line: bytes,
    expected_message: str,
) -> None:
    caplog.set_level(logging.INFO, logger=dnsdb.__name__)
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(
        monkeypatch,
        (
            b'{"cond":"begin"}\n',
            b'{"obj":{"rrname":"first.example.com."}}\n',
            last_line,
        ),
    )

    search = dnsdb.SearchDNSDB('example.com')
    await search.process()

    assert await search.get_hostnames() == {'first.example.com'}
    assert any(expected_message in message for message in caplog.messages)


@pytest.mark.asyncio
async def test_process_preserves_partial_results_on_midstream_timeout(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=dnsdb.__name__)
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(
        monkeypatch,
        (
            b'{"cond":"begin"}\n',
            b'{"obj":{"rrname":"first.example.com."}}\n',
        ),
        stream_error=TimeoutError(),
    )

    search = dnsdb.SearchDNSDB('example.com')
    await search.process()

    assert await search.get_hostnames() == {'first.example.com'}
    assert any('request failed' in message for message in caplog.messages)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('status', 'expected_error'),
    [
        (401, PermissionError),
        (429, ConnectionError),
        (503, ConnectionError),
    ],
)
async def test_process_exposes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    expected_error: type[Exception],
) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(monkeypatch, (), status=status)

    with pytest.raises(expected_error):
        await dnsdb.SearchDNSDB('example.com').process()
