import asyncio
import logging
import math
import ssl
import subprocess
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from theHarvester.lib import virtual_host as virtual_host_module
from theHarvester.lib.virtual_host import (
    VHOST_BODY_LIMIT,
    ProbeObservation,
    VirtualHostDiscoveryCancelled,
    VirtualHostDiscoveryResult,
    VirtualHostLimits,
    VirtualHostObservation,
    VirtualHostRequest,
    classify_virtual_host,
    discover_harvested_virtual_hosts,
    discover_virtual_hosts,
)


async def read_host(reader: asyncio.StreamReader) -> str:
    request = await reader.readuntil(b'\r\n\r\n')
    host_line = next(line for line in request.split(b'\r\n') if line.lower().startswith(b'host:'))
    return host_line.split(b':', 1)[1].strip().decode()


async def write_response(
    writer: asyncio.StreamWriter,
    *,
    status: bytes = b'200 OK',
    body: bytes = b'default page',
    headers: tuple[bytes, ...] = (),
    content_length: int | None = None,
) -> None:
    header_bytes = b''.join(header + b'\r\n' for header in headers)
    length = len(body) if content_length is None else content_length
    writer.write(
        b'HTTP/1.1 '
        + status
        + b'\r\n'
        + header_bytes
        + b'Content-Length: '
        + str(length).encode()
        + b'\r\nConnection: close\r\n\r\n'
        + body
    )
    await writer.drain()
    writer.close()
    await writer.wait_closed()


@asynccontextmanager
async def local_server(
    handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
    *,
    host: str = '127.0.0.1',
    ssl_context: ssl.SSLContext | None = None,
) -> AsyncIterator[int]:
    server = await asyncio.start_server(handler, host, 0, ssl=ssl_context)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


@pytest.fixture(scope='module')
def tls_cert_chain(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    tls_directory = tmp_path_factory.mktemp('vhost-tls')
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
            '/CN=example.com',
            '-keyout',
            str(private_key),
            '-out',
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    return certificate, private_key


def response(
    hostname: str,
    *,
    status: int = 200,
    body: bytes = b'default page',
    location: str | None = None,
) -> ProbeObservation:
    return ProbeObservation(
        hostname=hostname,
        http_host=hostname,
        tls_server_name=hostname,
        phase='body',
        status=status,
        location=location,
        body=body,
    )


def discovery_result(
    *,
    observations: tuple[VirtualHostObservation, ...] = (),
    request_count: int,
    attempted_candidate_count: int,
    stop_reason: str = 'completed',
    request_error_count: int = 0,
    request_error_types: tuple[str, ...] = (),
    scan_error_type: str | None = None,
) -> VirtualHostDiscoveryResult:
    return VirtualHostDiscoveryResult(
        context=response('192.0.2.20'),
        controls=(),
        observations=observations,
        request_count=request_count,
        attempted_candidate_count=attempted_candidate_count,
        stop_reason=stop_reason,
        request_error_count=request_error_count,
        request_error_types=request_error_types,
        scan_error_type=scan_error_type,
    )


def distinct_observation(endpoint: str, *, hostname: str = 'admin.example.com') -> VirtualHostObservation:
    controls = tuple(response(f'unknown-{index}.example.com') for index in range(3))
    return classify_virtual_host(
        endpoint,
        response('192.0.2.20'),
        response(hostname, status=401),
        controls,
    )


async def test_harvested_virtual_host_sweep_carries_unused_budget_forward(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    requests: list[VirtualHostRequest] = []

    async def fake_discover(request: VirtualHostRequest, **_kwargs):
        requests.append(request)
        return discovery_result(
            request_count=8,
            attempted_candidate_count=len(request.candidates),
        )

    monkeypatch.setattr(virtual_host_module, 'discover_virtual_hosts', fake_discover)

    with caplog.at_level(logging.INFO, logger=virtual_host_module.__name__):
        result = await discover_harvested_virtual_hosts(
            scope='Example.COM.',
            addresses=('2001:db8::20', '192.0.2.20'),
            candidates=('admin.example.com', 'panel.example.com'),
            limits=VirtualHostLimits(request_limit=40, runtime_seconds=20),
        )

    assert [request.endpoint for request in requests] == [
        'https://192.0.2.20:443/',
        'https://[2001:db8::20]:443/',
        'http://192.0.2.20:80/',
        'http://[2001:db8::20]:80/',
    ]
    assert [request.limits.request_limit for request in requests] == [10, 10, 12, 16]
    assert all(request.scope == 'example.com' for request in requests)
    assert all(request.candidates == ('admin.example.com', 'panel.example.com') for request in requests)
    assert result.request_count == 32
    assert result.endpoint_count == 4
    assert result.total_endpoint_count == 4
    assert result.candidate_endpoint_count == 8
    assert result.total_candidate_endpoint_count == 8
    assert result.stop_reason == 'completed'
    assert 'Virtual-host endpoint 1/4 started: candidates=2; request-limit=10' in caplog.text
    assert 'Virtual-host endpoint 4/4 finished: stop=completed; requests=8; candidates=2/2; errors=0' in caplog.text


async def test_harvested_virtual_host_sweep_reports_every_budget_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[VirtualHostRequest] = []

    async def fake_discover(request: VirtualHostRequest, **_kwargs):
        requests.append(request)
        return discovery_result(
            request_count=5,
            attempted_candidate_count=len(request.candidates),
        )

    monkeypatch.setattr(virtual_host_module, 'discover_virtual_hosts', fake_discover)

    result = await discover_harvested_virtual_hosts(
        scope='Example.COM.',
        addresses=('192.0.2.20', '2001:db8::20'),
        candidates=('a.example.com', 'preview.example.com'),
        limits=VirtualHostLimits(request_limit=10, runtime_seconds=20),
    )

    assert [request.endpoint for request in requests] == [
        'https://192.0.2.20:443/',
        'https://[2001:db8::20]:443/',
    ]
    assert all(request.candidates == ('a.example.com',) for request in requests)
    assert result.request_count == 10
    assert result.endpoint_count == 2
    assert result.total_endpoint_count == 4
    assert result.candidate_endpoint_count == 2
    assert result.total_candidate_endpoint_count == 8
    assert result.stop_reason == 'request-limit'


async def test_harvested_virtual_host_sweep_has_one_hard_runtime_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_discover(
        request: VirtualHostRequest,
        *,
        _preserve_partial_on_cancel: bool = False,
    ):
        assert _preserve_partial_on_cancel is True
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            partial = classify_virtual_host(
                request.endpoint,
                response('192.0.2.20'),
                response('admin.example.com', status=401),
                tuple(response(f'unknown-{index}.example.com') for index in range(3)),
            )
            return discovery_result(
                observations=(partial,),
                request_count=5,
                attempted_candidate_count=1,
                stop_reason='runtime-limit',
            )

    monkeypatch.setattr(virtual_host_module, 'discover_virtual_hosts', fake_discover)
    started = time.perf_counter()

    result = await discover_harvested_virtual_hosts(
        scope='example.com',
        addresses=('192.0.2.20',),
        candidates=('admin.example.com',),
        limits=VirtualHostLimits(request_limit=10, runtime_seconds=0.02),
    )

    assert time.perf_counter() - started < 0.2
    assert tuple(observation.hostname for observation in result.observations) == ('admin.example.com',)
    assert result.request_count == 5
    assert result.candidate_endpoint_count == 1
    assert result.total_candidate_endpoint_count == 2
    assert result.stop_reason == 'runtime-limit'


async def test_harvested_virtual_host_sweep_retains_completed_endpoints_after_a_later_scan_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_count = 0

    async def fake_discover(
        request: VirtualHostRequest,
        *,
        _preserve_partial_on_cancel: bool = False,
    ):
        nonlocal call_count
        assert _preserve_partial_on_cancel is True
        call_count += 1
        if call_count == 2:
            raise RuntimeError('endpoint failed')
        return discovery_result(
            observations=(distinct_observation(request.endpoint),),
            request_count=5,
            attempted_candidate_count=1,
        )

    monkeypatch.setattr(virtual_host_module, 'discover_virtual_hosts', fake_discover)
    result = await discover_harvested_virtual_hosts(
        scope='example.com',
        addresses=('192.0.2.20',),
        candidates=('admin.example.com',),
        limits=VirtualHostLimits(request_limit=10, runtime_seconds=10),
    )

    assert tuple(observation.endpoint for observation in result.observations) == ('https://192.0.2.20:443/',)
    assert result.request_count == 5
    assert result.candidate_endpoint_count == 1
    assert result.stop_reason == 'scan-error'
    assert result.scan_error_type == 'RuntimeError'


async def test_discovery_returns_an_earlier_batch_when_a_later_probe_crashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_probe(
        _session: object,
        _request: VirtualHostRequest,
        hostname: str | None,
    ) -> ProbeObservation:
        if hostname == 'login.example.com':
            raise RuntimeError('probe crashed')
        if hostname == 'admin.example.com':
            return response(hostname, status=401)
        return response(hostname or '192.0.2.20')

    monkeypatch.setattr(virtual_host_module, '_probe', fake_probe)

    result = await discover_virtual_hosts(
        VirtualHostRequest(
            endpoint='http://192.0.2.20/',
            scope='example.com',
            candidates=('admin.example.com', 'login.example.com'),
            limits=VirtualHostLimits(concurrency=1),
        )
    )

    assert tuple(observation.hostname for observation in result.observations) == ('admin.example.com',)
    assert result.observations[0].classification == 'distinct'
    assert result.request_count == 6
    assert result.attempted_candidate_count == 1
    assert result.stop_reason == 'scan-error'
    assert result.scan_error_type == 'RuntimeError'


async def test_harvested_virtual_host_sweep_keeps_same_endpoint_evidence_after_a_scan_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def fake_discover(request: VirtualHostRequest, **_kwargs: object) -> VirtualHostDiscoveryResult:
        calls.append(request.endpoint)
        return discovery_result(
            observations=(distinct_observation(request.endpoint),),
            request_count=6,
            attempted_candidate_count=1,
            stop_reason='scan-error',
            scan_error_type='RuntimeError',
        )

    monkeypatch.setattr(virtual_host_module, 'discover_virtual_hosts', fake_discover)

    result = await discover_harvested_virtual_hosts(
        scope='example.com',
        addresses=('192.0.2.20',),
        candidates=('admin.example.com', 'portal.example.com'),
        limits=VirtualHostLimits(request_limit=20, runtime_seconds=10),
    )

    assert calls == ['https://192.0.2.20:443/']
    assert tuple(observation.hostname for observation in result.observations) == ('admin.example.com',)
    assert result.request_count == 6
    assert result.candidate_endpoint_count == 1
    assert result.stop_reason == 'scan-error'
    assert result.scan_error_type == 'RuntimeError'


async def test_harvested_virtual_host_sweep_cancellation_carries_partial_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    second_endpoint_started = asyncio.Event()
    call_count = 0

    async def fake_discover(
        request: VirtualHostRequest,
        *,
        _preserve_partial_on_cancel: bool = False,
    ):
        nonlocal call_count
        assert _preserve_partial_on_cancel is True
        call_count += 1
        if call_count == 1:
            return discovery_result(
                observations=(distinct_observation(request.endpoint),),
                request_count=5,
                attempted_candidate_count=1,
            )
        second_endpoint_started.set()
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            return discovery_result(
                observations=(distinct_observation(request.endpoint),),
                request_count=5,
                attempted_candidate_count=1,
                stop_reason='runtime-limit',
            )

    monkeypatch.setattr(virtual_host_module, 'discover_virtual_hosts', fake_discover)
    task = asyncio.create_task(
        discover_harvested_virtual_hosts(
            scope='example.com',
            addresses=('192.0.2.20',),
            candidates=('admin.example.com',),
            limits=VirtualHostLimits(request_limit=10, runtime_seconds=10),
        )
    )
    await second_endpoint_started.wait()
    task.cancel()

    with pytest.raises(VirtualHostDiscoveryCancelled) as cancelled:
        await task

    result = cancelled.value.result
    assert tuple(observation.endpoint for observation in result.observations) == (
        'https://192.0.2.20:443/',
        'http://192.0.2.20:80/',
    )
    assert result.request_count == 10
    assert result.candidate_endpoint_count == 2
    assert result.stop_reason == 'cancelled'
    assert result.scan_error_type == 'CancelledError'


async def test_harvested_virtual_host_sweep_propagates_cancellation_during_deadline_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deadline_cancelled = asyncio.Event()

    async def fake_discover(
        _request: VirtualHostRequest,
        *,
        _preserve_partial_on_cancel: bool = False,
    ):
        assert _preserve_partial_on_cancel is True
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            deadline_cancelled.set()
            try:
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                return discovery_result(
                    request_count=1,
                    attempted_candidate_count=0,
                    stop_reason='runtime-limit',
                )

    monkeypatch.setattr(virtual_host_module, 'discover_virtual_hosts', fake_discover)
    task = asyncio.create_task(
        discover_harvested_virtual_hosts(
            scope='example.com',
            addresses=('192.0.2.20',),
            candidates=('admin.example.com',),
            limits=VirtualHostLimits(request_limit=10, runtime_seconds=0.02),
        )
    )
    await deadline_cancelled.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


def test_classifier_marks_a_candidate_matching_stable_controls_as_default() -> None:
    controls = tuple(response(f'unknown-{index}.example.com') for index in range(3))

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        response('admin.example.com'),
        controls,
    )

    assert observation.classification == 'default'
    assert observation.distinct_signals == ()


def test_classifier_marks_a_candidate_matching_the_raw_ip_context_as_default() -> None:
    controls = tuple(response(f'unknown-{index}.example.com') for index in range(3))

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10', status=401, body=b'raw endpoint'),
        response('admin.example.com', status=401, body=b'raw endpoint'),
        controls,
    )

    assert observation.classification == 'default'
    assert observation.distinct_signals == ()


def test_classifier_keeps_a_candidate_indeterminate_when_the_raw_ip_context_fails() -> None:
    context = ProbeObservation(
        hostname='192.0.2.10',
        http_host='192.0.2.10',
        tls_server_name=None,
        phase='connect',
        error_type='TimeoutError',
    )
    controls = tuple(response(f'unknown-{index}.example.com') for index in range(3))

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        context,
        response('admin.example.com', status=401),
        controls,
    )

    assert observation.classification == 'indeterminate'
    assert observation.distinct_signals == ()


def test_classifier_marks_a_stable_status_difference_as_distinct() -> None:
    controls = tuple(response(f'unknown-{index}.example.com') for index in range(3))

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        response('admin.example.com', status=401),
        controls,
    )

    assert observation.classification == 'distinct'
    assert observation.distinct_signals == ('status',)
    assert observation.control_phase == 'body'
    assert observation.control_status == 200
    assert observation.control_location is None
    assert observation.control_body_sha256 == 'de9adea2908417ad2b86d8812b598c24c80c3faf4b0bfa304c5530f391805894'
    assert observation.control_body_size == 12
    assert observation.control_body_truncated is False


def test_classifier_ignores_exact_candidate_reflection() -> None:
    controls = tuple(
        response(
            hostname,
            body=f'unknown host: {hostname}'.encode(),
            location=f'https://errors.example.test/?host={hostname}',
        )
        for hostname in (f'unknown-{index}.example.com' for index in range(3))
    )
    candidate = response(
        'admin.example.com',
        body=b'unknown host: admin.example.com',
        location='https://errors.example.test/?host=admin.example.com',
    )

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        candidate,
        controls,
    )

    assert observation.classification == 'default'
    assert observation.reflection_normalized is True


def test_classifier_does_not_normalize_an_authority_inside_a_larger_hostname() -> None:
    controls = tuple(
        response(hostname, body=f'unknown host: not{hostname}'.encode())
        for hostname in (f'unknown-{index}.example.com' for index in range(3))
    )

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        response('admin.example.com', body=b'unknown host: notadmin.example.com'),
        controls,
    )

    assert observation.classification == 'indeterminate'
    assert observation.reflection_normalized is False


def test_classifier_keeps_inconsistent_controls_indeterminate() -> None:
    controls = (
        response('unknown-0.example.com', body=b'first default'),
        response('unknown-1.example.com', body=b'second default'),
        response('unknown-2.example.com', body=b'third default'),
    )

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        response('admin.example.com', status=401, body=b'candidate'),
        controls,
    )

    assert observation.classification == 'indeterminate'


def test_classifier_keeps_a_candidate_indeterminate_when_all_controls_fail() -> None:
    controls = tuple(
        ProbeObservation(
            hostname=f'unknown-{index}.example.com',
            http_host=f'unknown-{index}.example.com',
            tls_server_name=f'unknown-{index}.example.com',
            phase='connect',
            error_type='TimeoutError',
        )
        for index in range(3)
    )

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        response('admin.example.com', status=401),
        controls,
    )

    assert observation.classification == 'indeterminate'
    assert observation.distinct_signals == ()


def test_classifier_keeps_an_ambiguous_candidate_failure_indeterminate() -> None:
    controls = tuple(response(f'unknown-{index}.example.com') for index in range(3))
    candidate = ProbeObservation(
        hostname='admin.example.com',
        http_host='admin.example.com',
        tls_server_name='admin.example.com',
        phase='connect',
        error_type='TimeoutError',
    )

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        candidate,
        controls,
    )

    assert observation.classification == 'indeterminate'


def test_classifier_requires_confirmation_for_a_body_only_difference() -> None:
    controls = tuple(response(f'unknown-{index}.example.com') for index in range(3))

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        response('admin.example.com', body=b'private page'),
        controls,
    )

    assert observation.classification == 'indeterminate'
    assert observation.distinct_signals == ('body_sha256',)
    assert observation.needs_confirmation is True


def test_classifier_accepts_a_repeatable_body_only_difference() -> None:
    controls = tuple(response(f'unknown-{index}.example.com') for index in range(3))
    candidate = response('admin.example.com', body=b'private page')

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        candidate,
        controls,
        confirmation=candidate,
    )

    assert observation.classification == 'distinct'
    assert observation.distinct_signals == ('body_sha256',)
    assert observation.needs_confirmation is False


def test_classifier_keeps_a_truncated_body_comparison_indeterminate() -> None:
    controls = tuple(response(f'unknown-{index}.example.com') for index in range(3))
    candidate = ProbeObservation(
        hostname='admin.example.com',
        http_host='admin.example.com',
        tls_server_name='admin.example.com',
        phase='body',
        status=200,
        body=b'default page',
        body_truncated=True,
    )

    observation = classify_virtual_host(
        'https://192.0.2.10:443/',
        response('192.0.2.10'),
        candidate,
        controls,
    )

    assert observation.classification == 'indeterminate'
    assert observation.body_truncated is True


def test_direct_request_construction_enforces_scope_and_literal_ip() -> None:
    with pytest.raises(ValueError, match='literal IP'):
        VirtualHostRequest(
            endpoint='https://edge.example.com/',
            scope='example.com',
            candidates=('admin.example.com',),
        )
    with pytest.raises(ValueError, match='outside authorized scope'):
        VirtualHostRequest(
            endpoint='https://192.0.2.10/',
            scope='example.com',
            candidates=('admin.attacker.test',),
        )


def test_request_rejects_explicit_port_zero() -> None:
    with pytest.raises(ValueError, match='port must be between 1 and 65535'):
        VirtualHostRequest(
            endpoint='http://192.0.2.10:0/',
            scope='example.com',
            candidates=('admin.example.com',),
        )


def test_request_accepts_the_authorized_scope_apex_for_conservative_classification() -> None:
    request = VirtualHostRequest(
        endpoint='http://192.0.2.10/',
        scope='example.com',
        candidates=('example.com',),
    )

    assert request.candidates == ('example.com',)


def test_request_rejects_a_shape_without_three_available_unknown_controls() -> None:
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'

    with pytest.raises(ValueError, match='fewer than three available unknown controls'):
        VirtualHostRequest(
            endpoint='http://192.0.2.10/',
            scope='example.com',
            candidates=tuple(f'{character}.example.com' for character in alphabet[:-2]),
        )


@pytest.mark.parametrize('invalid_value', [math.inf, math.nan])
def test_limits_reject_non_finite_time_bounds(invalid_value: float) -> None:
    with pytest.raises(ValueError, match='runtime seconds must be positive and finite'):
        VirtualHostLimits(runtime_seconds=invalid_value)
    with pytest.raises(ValueError, match='timeout seconds must be positive and finite'):
        VirtualHostLimits(timeout_seconds=invalid_value)


@pytest.mark.parametrize(
    ('field', 'invalid_value'),
    [('request_limit', math.inf), ('request_limit', True), ('concurrency', math.inf), ('concurrency', True)],
)
def test_limits_require_finite_integer_counts(field: str, invalid_value: float) -> None:
    with pytest.raises(ValueError, match='must be an integer'):
        VirtualHostLimits(**{field: invalid_value})  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_discovery_connects_to_the_literal_ip_and_sends_the_candidate_host() -> None:
    seen_hosts: list[str] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = await read_host(reader)
        seen_hosts.append(host)
        status = b'401 Unauthorized' if host == f'admin.example.com:{port}' else b'200 OK'
        await write_response(writer, status=status)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com',),
        )
        result = await discover_virtual_hosts(request)

    assert result.request_count == 5
    assert seen_hosts[0] == f'127.0.0.1:{port}'
    assert f'admin.example.com:{port}' in seen_hosts
    assert result.context.tls_verified is None
    assert result.observations[0].tls_verified is None
    assert result.observations[0].classification == 'distinct'


@pytest.mark.asyncio
async def test_discovery_keeps_the_authorized_scope_apex_indeterminate() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = await read_host(reader)
        status = b'401 Unauthorized' if host.startswith('example.com:') else b'200 OK'
        await write_response(writer, status=status)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('example.com',),
        )
        result = await discover_virtual_hosts(request)

    assert result.observations[0].status == 401
    assert result.observations[0].classification == 'indeterminate'
    assert result.observations[0].distinct_signals == ()


@pytest.mark.asyncio
async def test_discovery_records_the_ipv6_context_authority_exactly() -> None:
    seen_hosts: list[str] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = await read_host(reader)
        seen_hosts.append(host)
        status = b'401 Unauthorized' if host.startswith('admin.') else b'200 OK'
        await write_response(writer, status=status)

    try:
        async with local_server(handle, host='::1') as port:
            request = VirtualHostRequest(
                endpoint=f'http://[::1]:{port}/',
                scope='example.com',
                candidates=('admin.example.com',),
            )
            result = await discover_virtual_hosts(request)
    except OSError:
        pytest.skip('IPv6 loopback is unavailable')

    assert seen_hosts[0] == f'[::1]:{port}'
    assert result.context.http_host == seen_hosts[0]
    assert result.observations[0].classification == 'distinct'


@pytest.mark.asyncio
async def test_discovery_charges_body_confirmation_to_the_hard_request_budget() -> None:
    request_count = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal request_count
        host = await read_host(reader)
        request_count += 1
        body = b'private page' if host.startswith('one.') or host.startswith('two.') else b'default page'
        await write_response(writer, body=body)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('one.example.com', 'two.example.com'),
            limits=VirtualHostLimits(request_limit=6),
        )
        result = await discover_virtual_hosts(request)

    assert request_count == result.request_count == 6
    assert len(result.observations) == 1
    assert result.observations[0].classification == 'distinct'
    assert result.stop_reason == 'request-limit'


@pytest.mark.asyncio
async def test_discovery_reports_the_budget_stop_when_confirmation_cannot_run() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = await read_host(reader)
        body = b'private page' if host.startswith('admin.') else b'default page'
        await write_response(writer, body=body)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com',),
            limits=VirtualHostLimits(request_limit=5),
        )
        result = await discover_virtual_hosts(request)

    assert result.request_count == 5
    assert result.observations[0].needs_confirmation is True
    assert result.stop_reason == 'request-limit'


@pytest.mark.asyncio
async def test_discovery_respects_the_candidate_concurrency_limit() -> None:
    active_candidates = 0
    maximum_active_candidates = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal active_candidates, maximum_active_candidates
        host = await read_host(reader)
        is_candidate = host.startswith('candidate-')
        if is_candidate:
            active_candidates += 1
            maximum_active_candidates = max(maximum_active_candidates, active_candidates)
            await asyncio.sleep(0.02)
            active_candidates -= 1
        status = b'401 Unauthorized' if is_candidate else b'200 OK'
        await write_response(writer, status=status)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=tuple(f'candidate-{index}.example.com' for index in range(4)),
            limits=VirtualHostLimits(concurrency=2),
        )
        result = await discover_virtual_hosts(request)

    assert maximum_active_candidates == 2
    assert len(result.observations) == 4


@pytest.mark.asyncio
async def test_discovery_stops_at_the_shared_runtime_limit() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = await read_host(reader)
        if host.startswith('slow.'):
            await asyncio.sleep(0.2)
        await write_response(writer)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('slow.example.com',),
            limits=VirtualHostLimits(runtime_seconds=0.05, timeout_seconds=1),
        )
        started = time.monotonic()
        result = await discover_virtual_hosts(request)
        elapsed = time.monotonic() - started

    assert elapsed < 0.15
    assert result.request_count == 5
    assert result.observations == ()
    assert result.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_discovery_retains_controls_completed_before_the_runtime_limit() -> None:
    request_count = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal request_count
        await read_host(reader)
        request_count += 1
        if request_count == 3:
            await asyncio.sleep(0.2)
        await write_response(writer)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com',),
            limits=VirtualHostLimits(runtime_seconds=0.05, timeout_seconds=1),
        )
        result = await discover_virtual_hosts(request)

    assert result.request_count == 3
    assert len(result.controls) == 1
    assert result.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_discovery_retains_completed_evidence_at_the_runtime_limit() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = await read_host(reader)
        if host.startswith('slow.'):
            await asyncio.sleep(1)
        status = b'401 Unauthorized' if host.startswith('fast.') else b'200 OK'
        await write_response(writer, status=status)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('fast.example.com', 'slow.example.com'),
            limits=VirtualHostLimits(runtime_seconds=0.5, timeout_seconds=2, concurrency=1),
        )
        result = await discover_virtual_hosts(request)

    assert tuple(observation.hostname for observation in result.observations) == ('fast.example.com',)
    assert result.attempted_candidate_count == 1
    assert result.observations[0].classification == 'distinct'
    assert result.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_discovery_retains_a_completed_probe_from_a_timed_out_concurrent_batch() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = await read_host(reader)
        if host.startswith('slow.'):
            await asyncio.sleep(1)
        status = b'401 Unauthorized' if host.startswith('fast.') else b'200 OK'
        await write_response(writer, status=status)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('fast.example.com', 'slow.example.com'),
            limits=VirtualHostLimits(runtime_seconds=0.5, timeout_seconds=2, concurrency=2),
        )
        result = await discover_virtual_hosts(request)

    assert tuple(observation.hostname for observation in result.observations) == ('fast.example.com',)
    assert result.attempted_candidate_count == 1
    assert result.observations[0].classification == 'distinct'
    assert result.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_discovery_uses_controls_matching_each_candidate_name_shape() -> None:
    seen_hosts: list[str] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = (await read_host(reader)).split(':', 1)[0]
        seen_hosts.append(host)
        relative_depth = len(host.removesuffix('.example.com').rstrip('.').split('.'))
        status = b'404 Not Found' if relative_depth == 2 else b'200 OK'
        await write_response(writer, status=status)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com', 'admin.dev.example.com'),
        )
        result = await discover_virtual_hosts(request)

    control_depths = {len(control.hostname.removesuffix('.example.com').rstrip('.').split('.')) for control in result.controls}
    assert control_depths == {1, 2}
    assert len(result.controls) == 6
    assert tuple(observation.classification for observation in result.observations) == ('default', 'default')
    assert set(request.candidates) <= set(seen_hosts)


@pytest.mark.asyncio
async def test_discovery_records_a_per_request_timeout_as_bounded_evidence() -> None:
    request_count = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal request_count
        await read_host(reader)
        request_count += 1
        if request_count == 2:
            await asyncio.sleep(0.1)
        await write_response(writer)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com',),
            limits=VirtualHostLimits(runtime_seconds=1, timeout_seconds=0.02),
        )
        result = await discover_virtual_hosts(request)

    assert request_count == result.request_count == 5
    assert result.controls[0].error_type == 'TimeoutError'
    assert result.observations[0].classification == 'indeterminate'
    assert result.request_error_count == 1
    assert result.request_error_types == ('TimeoutError',)
    assert result.stop_reason == 'request-errors'


@pytest.mark.asyncio
async def test_discovery_preserves_headers_when_the_body_read_fails() -> None:
    request_count = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal request_count
        await read_host(reader)
        request_count += 1
        if request_count == 5:
            await write_response(writer, body=b'short', content_length=20)
        else:
            await write_response(writer)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com',),
        )
        result = await discover_virtual_hosts(request)

    observation = result.observations[0]
    assert observation.phase == 'headers'
    assert observation.status == 200
    assert observation.error_type == 'ClientPayloadError'
    assert observation.classification == 'indeterminate'


@pytest.mark.asyncio
async def test_discovery_caps_large_bodies_and_keeps_them_indeterminate() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = await read_host(reader)
        body = b'x' * (VHOST_BODY_LIMIT + 100) if host.startswith('admin.') else b'default page'
        await write_response(writer, body=body)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com',),
        )
        result = await discover_virtual_hosts(request)

    observation = result.observations[0]
    assert observation.body_size == VHOST_BODY_LIMIT
    assert observation.body_truncated is True
    assert observation.classification == 'indeterminate'


@pytest.mark.asyncio
async def test_discovery_preserves_cancellation_and_closes_the_connection() -> None:
    accepted = asyncio.Event()
    connection_closed = asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b'\r\n\r\n')
        accepted.set()
        await reader.read()
        connection_closed.set()
        writer.close()
        await writer.wait_closed()

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com',),
        )
        task = asyncio.create_task(discover_virtual_hosts(request))
        await asyncio.wait_for(accepted.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(connection_closed.wait(), timeout=1)


@pytest.mark.asyncio
async def test_discovery_records_redirects_without_following_them() -> None:
    paths: list[str] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await reader.readuntil(b'\r\n\r\n')
        request_line = request.split(b'\r\n', 1)[0].decode()
        paths.append(request_line.split()[1])
        host_line = next(line for line in request.split(b'\r\n') if line.lower().startswith(b'host:'))
        host = host_line.split(b':', 1)[1].strip().decode()
        if host.startswith('admin.'):
            await write_response(writer, status=b'302 Found', body=b'', headers=(b'Location: /followed',))
        else:
            await write_response(writer)

    async with local_server(handle) as port:
        request = VirtualHostRequest(
            endpoint=f'http://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com',),
        )
        result = await discover_virtual_hosts(request)

    assert paths == ['/'] * 5
    assert result.observations[0].status == 302
    assert result.observations[0].location == '/followed'


@pytest.mark.asyncio
async def test_https_discovery_does_not_retry_with_verification_disabled(
    tls_cert_chain: tuple[Path, Path],
) -> None:
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(*tls_cert_chain)
    received_requests = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal received_requests
        await read_host(reader)
        received_requests += 1
        writer.close()
        await writer.wait_closed()

    async with local_server(handle, ssl_context=server_context) as port:
        request = VirtualHostRequest(
            endpoint=f'https://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com',),
        )
        result = await discover_virtual_hosts(request)

    assert received_requests == 0
    assert result.request_count == 5
    assert result.context.phase == 'tls'
    assert all(control.phase == 'tls' for control in result.controls)
    assert result.observations[0].phase == 'tls'
    assert result.observations[0].tls_verified is True
    assert result.observations[0].classification == 'indeterminate'


@pytest.mark.asyncio
async def test_https_discovery_aligns_each_candidate_sni_and_host(
    tls_cert_chain: tuple[Path, Path],
) -> None:
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(*tls_cert_chain)
    server_names: dict[int, str | None] = {}
    received: list[tuple[str, str | None]] = []

    def record_server_name(ssl_object: ssl.SSLObject, server_name: str | None, _context: ssl.SSLContext) -> None:
        server_names[id(ssl_object)] = server_name

    server_context.sni_callback = record_server_name

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host = await read_host(reader)
        ssl_object = writer.get_extra_info('ssl_object')
        received.append((host, server_names[id(ssl_object)]))
        status = b'401 Unauthorized' if host.startswith('admin.') or host.startswith('portal.') else b'200 OK'
        await write_response(writer, status=status)

    async with local_server(handle, ssl_context=server_context) as port:
        request = VirtualHostRequest(
            endpoint=f'https://127.0.0.1:{port}/',
            scope='example.com',
            candidates=('admin.example.com', 'portal.example.com'),
            insecure=True,
        )
        result = await discover_virtual_hosts(request)

    candidate_pairs = [(host, sni) for host, sni in received if host.startswith(('admin.', 'portal.'))]
    assert candidate_pairs == [
        (f'admin.example.com:{port}', 'admin.example.com'),
        (f'portal.example.com:{port}', 'portal.example.com'),
    ]
    assert all(observation.tls_verified is False for observation in result.observations)
