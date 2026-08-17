from __future__ import annotations

import asyncio
import contextlib
import logging

import pytest

from theHarvester.discovery import dnsdb
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.source_execution import SourceExecutionReport


def _install_response(
    monkeypatch: pytest.MonkeyPatch,
    lines: tuple[bytes, ...],
    *,
    status: int = 200,
    stream_error: Exception | None = None,
) -> dict[str, object]:
    requested: dict[str, object] = {}

    class FakeResponse:
        def __init__(self) -> None:
            self.status = status
            self.headers: dict[str, str] = {}

        async def __aiter__(self):
            for line in lines:
                yield line.decode()
            if stream_error is not None:
                raise stream_error

    @contextlib.asynccontextmanager
    async def fake_stream_records(url: str, **kwargs: object):
        requested['url'] = url
        requested['stream'] = kwargs
        yield FakeResponse()

    async def private_transport_is_not_a_public_seam(*_args: object, **_kwargs: object) -> None:
        raise AssertionError('DNSDB must use AsyncFetcher.stream_records')

    monkeypatch.setattr(dnsdb.AsyncFetcher, 'stream_records', fake_stream_records)
    monkeypatch.setattr(dnsdb.AsyncFetcher, '_build_session', private_transport_is_not_a_public_seam)
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
    stream_options = requested['stream']
    assert isinstance(stream_options, dict)
    assert stream_options['headers'] == {
        'Accept': 'application/x-ndjson',
        'User-Agent': dnsdb.Core.get_user_agent(),
        'X-API-Key': 'dnsdb-test-key',
    }
    assert stream_options['framing'] == 'ndjson'
    assert stream_options['follow_redirects'] is False
    assert stream_options['request_timeout'] == 120


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

    stream_options = requested['stream']
    assert isinstance(stream_options, dict)
    assert stream_options['proxy'] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('last_line', 'expected_message', 'expected_report'),
    [
        (
            b'{"cond":"limited"}\n',
            'ended with limited',
            SourceExecutionReport('rate-limited', 'provider-limited'),
        ),
        (b'not-json\n', 'malformed NDJSON', SourceExecutionReport('failed', 'invalid-response')),
    ],
)
async def test_process_preserves_partial_results(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    last_line: bytes,
    expected_message: str,
    expected_report: SourceExecutionReport,
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
    report = await search.process()

    assert await search.get_hostnames() == {'first.example.com'}
    assert report == expected_report
    assert any(expected_message in message for message in caplog.messages)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('lines', 'expected_report'),
    [
        ((b'[]\n',), SourceExecutionReport('failed', 'invalid-response')),
        ((b'{"cond":"wrong"}\n',), SourceExecutionReport('failed', 'invalid-response')),
        (
            (b'{"cond":"begin"}\n', b'{"cond":"failed"}\n'),
            SourceExecutionReport('failed', 'provider-failed'),
        ),
        ((b'{"cond":"begin"}\n',), SourceExecutionReport('failed', 'invalid-response')),
        (
            (b'{"cond":"begin"}\n', b'{"cond":"wrong"}\n', b'{"cond":"succeeded"}\n'),
            SourceExecutionReport('failed', 'invalid-response'),
        ),
        (
            (b'{"cond":"begin"}\n', b'{"obj":[]}\n', b'{"cond":"succeeded"}\n'),
            SourceExecutionReport('failed', 'invalid-response'),
        ),
        (
            (b'{"cond":"begin"}\n', b'{"obj":{}}\n', b'{"cond":"succeeded"}\n'),
            SourceExecutionReport('failed', 'invalid-response'),
        ),
        (
            (b'{"cond":"begin"}\n', b'{"obj":{"rrname":7}}\n', b'{"cond":"succeeded"}\n'),
            SourceExecutionReport('failed', 'invalid-response'),
        ),
    ],
)
async def test_process_reports_abnormal_stream_termination(
    monkeypatch: pytest.MonkeyPatch,
    lines: tuple[bytes, ...],
    expected_report: SourceExecutionReport,
) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(monkeypatch, lines)

    assert await dnsdb.SearchDNSDB('example.com').process() == expected_report


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
        stream_error=dnsdb.ResponseStreamError('transport-error'),
    )

    search = dnsdb.SearchDNSDB('example.com')
    report = await search.process()

    assert await search.get_hostnames() == {'first.example.com'}
    assert report == SourceExecutionReport('failed', 'transport-error')
    assert any('request failed' in message for message in caplog.messages)


@pytest.mark.asyncio
async def test_process_reports_deeply_nested_json_as_invalid_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(monkeypatch, (b'{"cond":"begin"}\n', b'deeply-nested-json\n'))
    json_loads = dnsdb.json.loads

    def parse_record(line: str) -> object:
        if line.strip() == 'deeply-nested-json':
            raise RecursionError
        return json_loads(line)

    monkeypatch.setattr(dnsdb.json, 'loads', parse_record)

    assert await dnsdb.SearchDNSDB('example.com').process() == SourceExecutionReport('failed', 'invalid-response')


@pytest.mark.asyncio
async def test_process_propagates_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(
        monkeypatch,
        (b'{"cond":"begin"}\n',),
        stream_error=asyncio.CancelledError(),
    )

    with pytest.raises(asyncio.CancelledError):
        await dnsdb.SearchDNSDB('example.com').process()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('status', 'expected_report'),
    [
        (401, SourceExecutionReport('failed', 'access-denied')),
        (429, SourceExecutionReport('rate-limited', 'http-429')),
        (503, SourceExecutionReport('failed', 'http-503')),
    ],
)
async def test_process_reports_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    expected_report: SourceExecutionReport,
) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(monkeypatch, (), status=status)

    assert await dnsdb.SearchDNSDB('example.com').process() == expected_report


pytestmark = pytest.mark.provider_contract('dnsdb')
