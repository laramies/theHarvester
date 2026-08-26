import asyncio
import json
import ssl
import subprocess
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import pytest

from theHarvester.discovery import api_endpoints
from theHarvester.lib.core import FetcherResponse, ResponseStreamError


class FakeResponse:
    async def __aenter__(self) -> 'FakeResponse':
        return self

    async def __aexit__(self, *_args) -> None:
        return None


class FakeSession:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.requests: list[tuple[str, dict[str, object]]] = []

    async def __aenter__(self) -> 'FakeSession':
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    def get(self, url: str, **kwargs) -> FakeResponse:
        self.requests.append((url, kwargs))
        if self.error:
            raise self.error
        return FakeResponse()


@pytest.fixture(scope='module')
def api_tls_cert_chain(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    tls_directory = tmp_path_factory.mktemp('api-endpoint-tls')
    certificate = tls_directory / 'certificate.pem'
    private_key = tls_directory / 'private-key.pem'
    subprocess.run(
        [
            'openssl',
            'req',
            '-x509',
            '-newkey',
            'rsa:2048',
            '-nodes',
            '-sha256',
            '-days',
            '1',
            '-subj',
            '/CN=127.0.0.1',
            '-keyout',
            str(private_key),
            '-out',
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    return certificate, private_key


def test_process_response_extracts_only_string_json_parameter_names(monkeypatch):
    search = api_endpoints.SearchApiEndpoints('example.com')
    response = SimpleNamespace(
        status=200,
        headers={'Content-Type': 'application/json'},
        content=b'{"name": "value"}',
    )

    monkeypatch.setattr(api_endpoints.json, 'loads', lambda _content: {'name': 'value', 1: 'ignored'})

    result = search._process_response('https://example.com/api/v1/users', 'GET', response, 0.1)

    assert result is not None
    assert result.parameters == ['name']


def test_process_response_parses_json_once_independent_of_technology_count(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    search.tech_patterns = {f'tech-{index}': ['never-match'] for index in range(25)}
    response = SimpleNamespace(
        status=200,
        headers={'Content-Type': 'application/json'},
        content=b'{"first": 1, "second": 2}',
    )
    parse_count = 0

    def loads(_content: bytes) -> dict[str, str | int]:
        nonlocal parse_count
        parse_count += 1
        return {'openapi': '3.0', 'first': 1, 'second': 2}

    monkeypatch.setattr(api_endpoints.json, 'loads', loads)

    result = search._process_response('https://example.com/swagger', 'GET', response, 0.1)

    assert result is not None
    assert result.parameters == ['openapi', 'first', 'second']
    assert search.get_schema_detected() == {'https://example.com/swagger': {'openapi': '3.0', 'first': 1, 'second': 2}}
    assert parse_count == 1


def test_schema_getter_preserves_full_documents() -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    document = {
        'openapi': '3.1.0',
        'paths': {f'/resource/{index}': {'description': 'x' * 2048} for index in range(64)},
    }
    content = json.dumps(document).encode()

    search._process_response(
        'https://example.com/openapi.json',
        'GET',
        SimpleNamespace(status=200, headers={'content-type': 'application/json'}, body=content),
        0.1,
    )

    assert search.get_schema_detected() == {'https://example.com/openapi.json': document}


def test_api_endpoint_scan_defaults_to_direct_requests_with_redirects() -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')

    assert search.proxy is None
    assert search.follow_redirects is True
    assert search.concurrency == 10
    assert search.request_limit is None
    assert search.runtime_seconds is None
    assert api_endpoints.SearchApiEndpoints('example.com', concurrency=20).concurrency == 20


def test_api_endpoint_scan_accepts_explicitly_unlimited_library_overrides() -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', request_limit=None, runtime_seconds=None)

    assert search.request_limit is None
    assert search.runtime_seconds is None


@pytest.mark.parametrize('concurrency', [0, -1, True, 1.5])
def test_api_endpoint_scan_rejects_invalid_concurrency(concurrency: object) -> None:
    with pytest.raises(ValueError, match='concurrency must be a positive integer'):
        api_endpoints.SearchApiEndpoints('example.com', concurrency=concurrency)


@pytest.mark.parametrize(
    ('option', 'value'),
    [
        ('timeout', 0),
        ('request_limit', 0),
        ('runtime_seconds', 0),
        ('response_body_limit', 0),
    ],
)
def test_api_endpoint_scan_rejects_nonpositive_budgets(option: str, value: int) -> None:
    with pytest.raises(ValueError, match=option):
        api_endpoints.SearchApiEndpoints('example.com', **{option: value})


@pytest.mark.parametrize('option', ['timeout', 'runtime_seconds'])
@pytest.mark.parametrize('value', [float('nan'), float('inf'), float('-inf')])
def test_api_endpoint_scan_rejects_nonfinite_time_budgets(option: str, value: float) -> None:
    with pytest.raises(ValueError, match=option):
        api_endpoints.SearchApiEndpoints('example.com', **{option: value})


def test_api_endpoint_scan_rejects_fractional_request_timeout() -> None:
    with pytest.raises(ValueError, match='timeout must be a positive integer'):
        api_endpoints.SearchApiEndpoints('example.com', timeout=1.5)


@pytest.mark.asyncio
async def test_api_endpoint_scan_bounds_active_and_pending_work_and_preserves_order(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=3, exact_paths=True)
    paths = [f'/api/{index}' for index in range(1_001)]
    active = 0
    peak_active = 0
    peak_pending = 0
    first_release = asyncio.Event()
    baseline_tasks = len(asyncio.all_tasks())

    monkeypatch.setattr(search, '_load_wordlist', lambda: paths)

    async def detect_schema(_path: str = '') -> str:
        return 'https'

    async def fetch(session=None, url: str = '', **_kwargs) -> FetcherResponse:
        nonlocal active, peak_active, peak_pending
        assert session is not None
        active += 1
        peak_active = max(peak_active, active)
        peak_pending = max(peak_pending, len(asyncio.all_tasks()) - baseline_tasks)
        try:
            if url.endswith('/0'):
                await first_release.wait()
            else:
                first_release.set()
            await asyncio.sleep(0)
            return FetcherResponse(body='{}', status=200, headers={'content-type': 'application/json'})
        finally:
            active -= 1

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    expected_urls = [f'https://example.com{path}' for path in paths]
    assert [result['url'] for result in search.get_detailed_results()] == expected_urls
    assert search.request_count == len(paths) + 1  # schema detection plus every endpoint
    assert peak_active == 3
    assert peak_pending <= 3
    assert not any(task.get_name().startswith('api-endpoint-worker-') for task in asyncio.all_tasks())


@pytest.mark.asyncio
async def test_concurrent_api_endpoint_scans_have_independent_worker_limits(monkeypatch) -> None:
    scans = [api_endpoints.SearchApiEndpoints(f'{index}.example.com', concurrency=1, exact_paths=True) for index in range(2)]
    active = 0
    peak_active = 0
    both_started = asyncio.Event()
    for search in scans:
        monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])

        async def detect_schema(_path: str = '') -> str:
            return 'https'

        monkeypatch.setattr(search, '_detect_schema', detect_schema)

    async def fetch(*_args, **_kwargs) -> FetcherResponse:
        nonlocal active, peak_active
        active += 1
        peak_active = max(peak_active, active)
        if active == 2:
            both_started.set()
        try:
            await both_started.wait()
            return FetcherResponse(body='{}', status=200, headers={})
        finally:
            active -= 1

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await asyncio.gather(*(search.do_search() for search in scans))

    assert peak_active == 2
    assert [len(search.get_found_endpoints()) for search in scans] == [1, 1]


@pytest.mark.asyncio
async def test_api_endpoint_scan_reuses_keepalive_transport_with_bounded_connector(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=10, exact_paths=True)
    connector_options: dict[str, object] = {}
    sessions: list[object] = []
    ssl_policies: list[object] = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/one', '/two'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    def connector(**kwargs):
        connector_options.update(kwargs)
        return object()

    class Session:
        def __init__(self, **kwargs) -> None:
            self.headers = kwargs['headers']
            self.connector = kwargs.get('connector')
            self.closed = False
            sessions.append(self)

        async def close(self) -> None:
            self.closed = True

    async def fetch(session=None, url: str = '', **kwargs) -> FetcherResponse:
        assert session is sessions[0]
        ssl_policies.append(kwargs['verify'])
        return FetcherResponse(body=url, status=200, headers={})

    monkeypatch.setattr(api_endpoints.aiohttp, 'TCPConnector', connector)
    monkeypatch.setattr(api_endpoints.aiohttp, 'ClientSession', Session)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert connector_options == {'limit': 2, 'limit_per_host': 2, 'ssl': True}
    assert sessions[0].connector is not None
    assert 'Connection' not in sessions[0].headers
    assert ssl_policies == [True, True]
    assert ssl_policies[0] is ssl_policies[1]
    assert sessions[0].closed is True


@pytest.mark.asyncio
async def test_api_endpoint_scan_closes_connector_when_session_construction_fails(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', exact_paths=True)

    class Connector:
        def __init__(self) -> None:
            self.closed = False

        async def close(self) -> None:
            self.closed = True

    connector = Connector()
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])
    monkeypatch.setattr(api_endpoints.aiohttp, 'TCPConnector', lambda **_kwargs: connector)

    def fail_session(**_kwargs):
        raise RuntimeError('session construction failed')

    monkeypatch.setattr(api_endpoints.aiohttp, 'ClientSession', fail_session)

    await search.do_search()

    assert connector.closed is True
    assert search.scan_error_type == 'RuntimeError'
    assert search.stop_reason == 'scan-error'


@pytest.mark.asyncio
async def test_api_endpoint_scan_reuses_one_real_https_connection(
    monkeypatch: pytest.MonkeyPatch,
    api_tls_cert_chain: tuple[Path, Path],
) -> None:
    certificate, private_key = api_tls_cert_chain
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, private_key)
    accepted_connections = 0
    requested_paths: list[str] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal accepted_connections
        accepted_connections += 1
        try:
            while True:
                try:
                    request = await reader.readuntil(b'\r\n\r\n')
                except asyncio.IncompleteReadError:
                    break
                requested_paths.append(request.split(b' ', 2)[1].decode())
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}')
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, '127.0.0.1', 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    search = api_endpoints.SearchApiEndpoints(
        f'127.0.0.1:{port}',
        concurrency=1,
        exact_paths=True,
        verify_ssl=False,
    )
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/one', '/two'])

    try:
        await search.do_search()
    finally:
        server.close()
        await server.wait_closed()

    assert list(search.get_found_endpoints()) == [
        f'https://127.0.0.1:{port}/one',
        f'https://127.0.0.1:{port}/two',
    ]
    assert requested_paths == ['/one', '/one', '/two']
    assert search._ssl_policy is False
    assert accepted_connections == 1


@pytest.mark.asyncio
async def test_api_endpoint_scan_stops_at_the_total_request_budget(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints(
        'example.com',
        concurrency=3,
        exact_paths=True,
        request_limit=3,
    )
    requested_urls: list[str] = []
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/one', '/two', '/three', '/four'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    async def fetch(session=None, url: str = '', **_kwargs) -> FetcherResponse:
        requested_urls.append(url)
        await asyncio.sleep(0)
        return FetcherResponse(body='{}', status=200, headers={})

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert search.request_count == 3
    assert search.stop_reason == 'request-limit'
    assert requested_urls == ['https://example.com/one', 'https://example.com/two']
    assert list(search.get_found_endpoints()) == requested_urls


@pytest.mark.asyncio
async def test_api_endpoint_scan_retains_completed_results_at_the_runtime_budget(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints(
        'example.com',
        concurrency=1,
        exact_paths=True,
        runtime_seconds=0.01,
    )
    never = asyncio.Event()
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/done', '/slow'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    async def fetch(session=None, url: str = '', **_kwargs) -> FetcherResponse:
        if url.endswith('/slow'):
            await never.wait()
        return FetcherResponse(body='{}', status=200, headers={})

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert search.stop_reason == 'runtime-limit'
    assert list(search.get_found_endpoints()) == ['https://example.com/done']
    assert not any(task.get_name().startswith('api-endpoint-worker-') for task in asyncio.all_tasks())


@pytest.mark.asyncio
async def test_api_endpoint_scan_runtime_budget_includes_post_scan_analysis(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', exact_paths=True, runtime_seconds=0.01)
    never = asyncio.Event()
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))
    monkeypatch.setattr(search, '_post_scan_analysis', never.wait)

    async def fetch(*_args, **_kwargs) -> FetcherResponse:
        return FetcherResponse(body='{}', status=200, headers={})

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert search.stop_reason == 'runtime-limit'
    assert list(search.get_found_endpoints()) == ['https://example.com/api']


@pytest.mark.asyncio
async def test_api_endpoint_scan_cancellation_awaits_workers_and_closes_transport(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=3, exact_paths=True)
    sessions: list[object] = []
    active = 0
    all_started = asyncio.Event()
    never = asyncio.Event()

    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/one', '/two', '/three'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))
    monkeypatch.setattr(api_endpoints.aiohttp, 'TCPConnector', lambda **_kwargs: object())

    class Session:
        def __init__(self, **_kwargs) -> None:
            self.closed = False
            sessions.append(self)

        async def close(self) -> None:
            self.closed = True

    async def fetch(session=None, url: str = '', **_kwargs) -> FetcherResponse:
        nonlocal active
        active += 1
        if active == 3:
            all_started.set()
        try:
            await never.wait()
            return FetcherResponse(body=url, status=200, headers={})
        finally:
            active -= 1

    monkeypatch.setattr(api_endpoints.aiohttp, 'ClientSession', Session)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    scan = asyncio.create_task(search.do_search())
    await all_started.wait()
    scan.cancel()

    with pytest.raises(asyncio.CancelledError):
        await scan

    assert search.stop_reason == 'cancelled'
    assert search.scan_error_type == 'CancelledError'
    assert active == 0
    assert sessions[0].closed is True
    assert not any(task.get_name().startswith('api-endpoint-worker-') for task in asyncio.all_tasks())


@pytest.mark.asyncio
async def test_api_endpoint_scan_preserves_first_cancellation_during_worker_drain(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=2, exact_paths=True)
    first_cancel = asyncio.CancelledError('operator-stop-first')
    both_started = asyncio.Event()
    cleanup_started = asyncio.Event()
    release_cleanup = asyncio.Event()
    started = 0
    sessions: list[object] = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/cancel', '/slow'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))
    monkeypatch.setattr(api_endpoints.aiohttp, 'TCPConnector', lambda **_kwargs: object())

    class Session:
        def __init__(self, **_kwargs) -> None:
            self.closed = False
            sessions.append(self)

        async def close(self) -> None:
            self.closed = True

    async def fetch(session=None, url: str = '', **_kwargs) -> FetcherResponse:
        nonlocal started
        started += 1
        if started == 2:
            both_started.set()
        await both_started.wait()
        if url.endswith('/cancel'):
            raise first_cancel
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cleanup_started.set()
            await release_cleanup.wait()
            raise

    monkeypatch.setattr(api_endpoints.aiohttp, 'ClientSession', Session)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    scan = asyncio.create_task(search.do_search())
    await cleanup_started.wait()
    scan.cancel('operator-stop-second')
    release_cleanup.set()

    with pytest.raises(asyncio.CancelledError) as raised:
        await scan

    assert raised.value is first_cancel
    assert search.stop_reason == 'cancelled'
    assert sessions[0].closed is True
    assert not any(task.get_name().startswith('api-endpoint-worker-') for task in asyncio.all_tasks())


@pytest.mark.asyncio
async def test_api_endpoint_scan_preserves_first_cancellation_while_closing_session(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=1, exact_paths=True)
    first_cancel = asyncio.CancelledError('operator-stop-first')
    close_started = asyncio.Event()
    release_close = asyncio.Event()
    sessions: list[object] = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/cancel'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))
    monkeypatch.setattr(api_endpoints.aiohttp, 'TCPConnector', lambda **_kwargs: object())

    class Session:
        def __init__(self, **_kwargs) -> None:
            self.closed = False
            sessions.append(self)

        async def close(self) -> None:
            close_started.set()
            await release_close.wait()
            self.closed = True

    async def fetch(*_args, **_kwargs) -> FetcherResponse:
        raise first_cancel

    monkeypatch.setattr(api_endpoints.aiohttp, 'ClientSession', Session)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    scan = asyncio.create_task(search.do_search())
    await close_started.wait()
    scan.cancel('operator-stop-second')
    release_close.set()

    with pytest.raises(asyncio.CancelledError) as raised:
        await scan

    assert raised.value is first_cancel
    assert search.stop_reason == 'cancelled'
    assert sessions[0].closed is True
    assert not any(task.get_name() == 'api-endpoint-session-close' for task in asyncio.all_tasks())


@pytest.mark.asyncio
async def test_api_endpoint_scan_keeps_oversized_response_evidence_and_scans_siblings(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints(
        'example.com',
        concurrency=1,
        exact_paths=True,
        response_body_limit=4,
    )
    requested_urls: list[str] = []
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/large', '/sibling'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    async def fetch(*_args, url: str = '', **kwargs) -> FetcherResponse:
        requested_urls.append(url)
        assert kwargs['response_byte_limit'] == 4
        assert 'response_byte_account' not in kwargs
        if url.endswith('/large'):
            raise ResponseStreamError(
                'response-limit',
                status=206,
                headers={
                    'allow': 'GET, HEAD, OPTIONS',
                    'content-type': 'application/json',
                    'set-cookie': 'secret',
                    'x-api-key': 'reflected-secret',
                    'x-auth-token': 'reflected-secret',
                    'x-csrf-token': 'reflected-secret',
                },
            )
        return FetcherResponse(body='{}', status=200, headers={})

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert search.stop_reason == 'request-errors'
    assert search.scan_error_type is None
    assert search.request_error_count == 1
    assert search.request_error_types == {'ResponseLimitError'}
    assert search.request_count == 3
    assert requested_urls == ['https://example.com/large', 'https://example.com/sibling']
    large = search.get_found_endpoints()['https://example.com/large']
    assert large.status_code == 206
    assert large.response_headers == {
        'allow': 'GET, HEAD, OPTIONS',
        'content-type': 'application/json',
    }
    assert large.body_truncated is True
    assert list(search.get_found_endpoints()) == requested_urls


@pytest.mark.asyncio
async def test_api_endpoint_scan_accepts_bodies_over_the_former_cumulative_budget(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints(
        'example.com',
        concurrency=1,
        exact_paths=True,
        response_body_limit=512 * 1024,
    )
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/one', '/two', '/three'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    async def fetch(*_args, **kwargs) -> FetcherResponse:
        assert kwargs['response_byte_limit'] == 512 * 1024
        assert 'response_byte_account' not in kwargs
        return FetcherResponse(body='x' * (512 * 1024), status=200, headers={})

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert list(search.get_found_endpoints()) == [
        'https://example.com/one',
        'https://example.com/two',
        'https://example.com/three',
    ]
    assert sum(search.response_sizes.values()) > 1024 * 1024
    assert search.stop_reason is None
    assert search.request_error_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('limited_status', 'headers', 'expected_delay'),
    [
        (429, {'Retry-After': '2'}, 2.25),
        (503, {'Retry-After': 'invalid'}, 0.75),
        (503, {'Retry-After': 'Fri, 31 Dec 2099 23:59:59 GMT'}, 30.0),
    ],
)
async def test_api_endpoint_scan_retries_rate_limits_with_bounded_jitter(
    monkeypatch,
    limited_status: int,
    headers: dict[str, str],
    expected_delay: float,
) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=1, exact_paths=True)
    responses = iter(
        [
            FetcherResponse(body='limited', status=limited_status, headers=headers),
            FetcherResponse(body='{}', status=200, headers={'content-type': 'application/json'}),
        ]
    )
    sleeps: list[float] = []
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])
    monkeypatch.setattr(api_endpoints.random, 'uniform', lambda _start, _end: 0.25)

    async def detect_schema(_path: str = '') -> str:
        return 'https'

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    async def fetch(*_args, **_kwargs) -> FetcherResponse:
        return next(responses)

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.asyncio, 'sleep', sleep)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    result = search.get_found_endpoints()['https://example.com/api']
    assert result.status_code == 200
    assert search.request_count == 3
    assert sleeps == [expected_delay]
    assert search.get_rate_limits() == {}


@pytest.mark.asyncio
@pytest.mark.parametrize('limited_status', [429, 503])
async def test_api_endpoint_scan_retries_oversized_rate_limit_responses(monkeypatch, limited_status: int) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=1, exact_paths=True)
    calls = 0
    sleeps: list[float] = []
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])

    async def detect_schema(_path: str = '') -> str:
        return 'https'

    async def fetch(*_args, **_kwargs) -> FetcherResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ResponseStreamError('response-limit', status=limited_status, headers={'retry-after': '0'})
        return FetcherResponse(body='{}', status=200, headers={'content-type': 'application/json'})

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(api_endpoints.random, 'uniform', lambda _start, _end: 0.25)
    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.asyncio, 'sleep', sleep)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert calls == 2
    assert sleeps == [0.25]
    assert search.get_found_endpoints()['https://example.com/api'].status_code == 200
    assert search.request_error_count == 0
    assert search.request_error_types == set()


@pytest.mark.asyncio
async def test_api_endpoint_scan_blocks_redirects_outside_the_authorized_target(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=1, exact_paths=True)
    requests: list[tuple[str, bool]] = []
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    async def fetch(*_args, url: str = '', **kwargs) -> FetcherResponse:
        requests.append((url, kwargs['follow_redirects']))
        assert url == 'https://example.com/api'
        return FetcherResponse(body='', status=302, headers={'location': 'https://outside.invalid/collect'})

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert requests == [('https://example.com/api', False)]
    assert search.request_error_count == 1
    assert search.request_error_types == {'RedirectScopeError'}
    assert search.stop_reason == 'request-errors'
    assert search.get_found_endpoints()['https://example.com/api'].response_headers == {
        'location': 'https://outside.invalid/collect'
    }


@pytest.mark.asyncio
async def test_api_endpoint_scan_follows_redirects_within_the_authorized_target(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=1, exact_paths=True)
    requests: list[tuple[str, bool]] = []
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    async def fetch(*_args, url: str = '', **kwargs) -> FetcherResponse:
        requests.append((url, kwargs['follow_redirects']))
        if url.endswith('/api'):
            return FetcherResponse(body='', status=302, headers={'location': '/api/v2'})
        return FetcherResponse(body='{}', status=200, headers={'content-type': 'application/json'})

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert requests == [
        ('https://example.com/api', False),
        ('https://example.com/api/v2', False),
    ]
    assert search.request_count == 3
    assert search.stop_reason is None
    assert search.get_found_endpoints()['https://example.com/api'].status_code == 200


@pytest.mark.asyncio
async def test_api_endpoint_scan_follows_oversized_redirects_within_the_authorized_target(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=1, exact_paths=True)
    requests: list[str] = []
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    async def fetch(*_args, url: str = '', **_kwargs) -> FetcherResponse:
        requests.append(url)
        if url.endswith('/api'):
            raise ResponseStreamError('response-limit', status=302, headers={'location': '/api/v2'})
        return FetcherResponse(body='{}', status=200, headers={'content-type': 'application/json'})

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert requests == ['https://example.com/api', 'https://example.com/api/v2']
    assert search.request_error_count == 0
    assert search.request_error_types == set()
    assert search.get_found_endpoints()['https://example.com/api'].status_code == 200


@pytest.mark.asyncio
async def test_api_endpoint_scan_blocks_oversized_redirects_outside_the_authorized_target(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=1, exact_paths=True)
    requests: list[str] = []
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    async def fetch(*_args, url: str = '', **_kwargs) -> FetcherResponse:
        requests.append(url)
        raise ResponseStreamError(
            'response-limit',
            status=302,
            headers={'location': 'https://outside.invalid/collect'},
        )

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert requests == ['https://example.com/api']
    assert search.request_error_count == 1
    assert search.request_error_types == {'RedirectScopeError'}
    result = search.get_found_endpoints()['https://example.com/api']
    assert result.status_code == 302
    assert result.body_truncated is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('follow_redirects', 'headers'),
    [
        (False, {'location': '/api/v2'}),
        (True, {}),
    ],
)
async def test_api_endpoint_scan_reports_terminal_oversized_redirects_as_truncated(
    monkeypatch,
    follow_redirects: bool,
    headers: dict[str, str],
) -> None:
    search = api_endpoints.SearchApiEndpoints(
        'example.com',
        concurrency=1,
        exact_paths=True,
        follow_redirects=follow_redirects,
    )
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])
    monkeypatch.setattr(search, '_detect_schema', lambda _path='': asyncio.sleep(0, result='https'))

    async def fetch(*_args, **_kwargs) -> FetcherResponse:
        raise ResponseStreamError('response-limit', status=302, headers=headers)

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert search.request_error_count == 1
    assert search.request_error_types == {'ResponseLimitError'}
    assert search.stop_reason == 'request-errors'
    result = search.get_found_endpoints()['https://example.com/api']
    assert result.status_code == 302
    assert result.body_truncated is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('limited_status', 'expected_stop_reason', 'expected_error_types'),
    [
        (429, 'rate-limited', set()),
        (503, 'request-errors', {'HTTP503Error'}),
    ],
)
async def test_api_endpoint_scan_caps_retries_with_a_truthful_outcome(
    monkeypatch,
    limited_status: int,
    expected_stop_reason: str,
    expected_error_types: set[str],
) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', concurrency=1, exact_paths=True)
    calls = 0
    monkeypatch.setattr(search, '_load_wordlist', lambda: ['/api'])

    async def detect_schema(_path: str = '') -> str:
        return 'https'

    async def fetch(*_args, **_kwargs) -> FetcherResponse:
        nonlocal calls
        calls += 1
        return FetcherResponse(body='unavailable', status=limited_status, headers={'retry-after': '0'})

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.asyncio, 'sleep', no_sleep)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert calls == search.MAX_RETRIES + 1
    assert search.request_count == calls + 1
    assert search.get_found_endpoints()['https://example.com/api'].status_code == limited_status
    assert search.stop_reason == expected_stop_reason
    assert search.request_error_count == int(limited_status == 503)
    assert search.request_error_types == expected_error_types


@pytest.mark.asyncio
async def test_api_endpoint_scan_uses_only_observational_http_methods(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('192.0.2.1')
    search.common_api_paths = ['/api']
    methods = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def detect_schema():
        return 'https'

    async def fetch(*_args, method='GET', **_kwargs):
        methods.append(method)
        return ''

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert methods == ['GET', 'HEAD', 'OPTIONS']


@pytest.mark.asyncio
async def test_api_endpoint_scan_uses_only_the_configured_wordlist(monkeypatch, tmp_path) -> None:
    wordlist = tmp_path / 'operator-paths.txt'
    wordlist.write_text('/health\n', encoding='utf-8')
    search = api_endpoints.SearchApiEndpoints('example.com', wordlist=str(wordlist), exact_paths=True)
    detected_paths: list[str] = []
    requested_urls: list[str] = []

    async def detect_schema(path: str = '') -> str:
        detected_paths.append(path)
        return 'https'

    async def fetch(url: str, *_args, **_kwargs):
        requested_urls.append(url)
        return ''

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert detected_paths == ['/health']
    assert requested_urls == ['https://example.com/health'] * 3


@pytest.mark.asyncio
async def test_schema_detection_can_probe_an_exact_listed_path() -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', exact_paths=True)
    session = FakeSession()
    search._session = session

    assert await search._detect_schema('/health') == 'https'
    assert session.requests[0][0] == 'https://example.com/health'


@pytest.mark.asyncio
async def test_api_endpoint_scan_exposes_shared_fetcher_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    search.common_api_paths = ['/api']
    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def detect_schema() -> str:
        return 'https'

    async def fetch(*_args, **kwargs):
        assert kwargs['include_metadata'] is True
        assert kwargs['request_timeout'] == 10
        assert kwargs['response_byte_limit'] == 1024 * 1024
        return FetcherResponse(
            body='{"status":"ok"}',
            status=200,
            headers={'content-type': 'application/json'},
        )

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    result = search.get_found_endpoints()['https://example.com/api']
    assert result.status_code == 200
    assert result.method == 'GET'
    assert result.content_type == 'application/json'
    assert result.content_length == len('{"status":"ok"}')
    assert result.content_preview == '{"status":"ok"}'


@pytest.mark.asyncio
async def test_api_endpoint_scan_counts_suppressed_request_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    search.common_api_paths = ['/api']
    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def detect_schema() -> str:
        return 'https'

    async def fail_request(*_args, **kwargs):
        assert kwargs['include_metadata'] is True
        return None

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fail_request)

    await search.do_search()

    assert search.request_error_count == 3
    assert search.request_error_types == {'TransportError'}
    assert search.get_found_endpoints() == {}


@pytest.mark.asyncio
async def test_api_endpoint_scan_reports_suppressed_top_level_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')

    async def fail_schema_detection() -> str:
        raise RuntimeError('scan setup failed')

    monkeypatch.setattr(search, '_detect_schema', fail_schema_detection)

    assert await search.do_search() is None
    assert search.scan_error_type == 'RuntimeError'


@pytest.mark.asyncio
async def test_api_endpoint_scan_allows_an_operator_selected_private_target(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('100.64.0.1')
    search.common_api_paths = ['/api']
    requests = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def detect_schema():
        return 'https'

    async def fetch(*_args, **_kwargs):
        requests.append(True)
        return ''

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert requests == [True, True, True]


@pytest.mark.asyncio
async def test_api_endpoint_scan_uses_a_configured_proxy(monkeypatch) -> None:
    proxy = 'http://proxy.example:8080'
    search = api_endpoints.SearchApiEndpoints('192.0.2.1', proxy=proxy)
    search.common_api_paths = ['/api']
    requests = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def detect_schema():
        return 'https'

    async def fetch(*_args, **kwargs):
        requests.append((kwargs['proxy'], kwargs['follow_redirects']))
        return ''

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert requests == [(proxy, False), (proxy, False), (proxy, False)]


@pytest.mark.asyncio
async def test_api_endpoint_scan_builds_one_socks_proxy_session(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = 'socks5://proxy.example:1080'
    search = api_endpoints.SearchApiEndpoints('192.0.2.1', proxy=proxy)
    search.common_api_paths = ['/api']
    connector_calls: list[tuple[str | None, str | None]] = []
    requests: list[tuple[object, str | None]] = []
    connector = object()

    class OwnedSession:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs['connector'] is connector
            self.closed = False
            owned_sessions.append(self)

        async def close(self) -> None:
            self.closed = True

    owned_sessions: list[OwnedSession] = []

    async def create_connector(
        proxy_url: str | None,
        proxy_type: str | None,
        _ssl_context: object,
    ) -> object:
        connector_calls.append((proxy_url, proxy_type))
        return connector

    async def detect_schema() -> str:
        return 'https'

    async def fetch(*_args, **kwargs) -> None:
        requests.append((kwargs['session'], kwargs['proxy']))
        return None

    monkeypatch.setattr(search, '_load_wordlist', lambda: [])
    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, '_create_connector', create_connector)
    monkeypatch.setattr(api_endpoints.aiohttp, 'ClientSession', OwnedSession)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert connector_calls == [(proxy, 'socks5')]
    assert len(owned_sessions) == 1
    assert requests == [(owned_sessions[0], proxy)] * 3
    assert owned_sessions[0].closed is True


@pytest.mark.parametrize('error', [aiohttp.ClientConnectionError(), TimeoutError()])
@pytest.mark.asyncio
async def test_detect_schema_falls_back_only_when_https_cannot_connect(monkeypatch, error: Exception) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    search._session = FakeSession(error)

    assert await search._detect_schema() == 'http'


@pytest.mark.asyncio
async def test_detect_schema_does_not_downgrade_after_https_client_error(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    search._session = FakeSession(aiohttp.ClientPayloadError('bad payload'))

    with pytest.raises(aiohttp.ClientPayloadError, match='bad payload'):
        await search._detect_schema()


@pytest.mark.asyncio
async def test_detect_schema_reuses_session_with_configured_request_policy(monkeypatch) -> None:
    session = FakeSession()
    search = api_endpoints.SearchApiEndpoints('example.com', follow_redirects=True)
    search._session = session

    monkeypatch.setattr(
        api_endpoints.aiohttp,
        'ClientSession',
        lambda **_kwargs: pytest.fail('schema detection must reuse the scan session'),
    )

    assert await search._detect_schema() == 'https'
    assert session.requests == [
        (
            'https://example.com',
            {'ssl': True, 'allow_redirects': False},
        )
    ]
