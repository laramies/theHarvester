import asyncio
import tracemalloc
from types import SimpleNamespace
from typing import ClassVar

import pytest

from theHarvester.discovery import dnssearch
from theHarvester.lib import hostchecker


@pytest.mark.asyncio
async def test_check_deduplicates_candidates_and_bounds_active_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    query_counts: dict[tuple[str, str], int] = {}
    active_queries: dict[str, int] = {}
    peak_active_hosts = 0
    closed = False

    class FakeResolver:
        async def query_dns(self, host: str, record_type: str):
            nonlocal peak_active_hosts
            query_counts[host, record_type] = query_counts.get((host, record_type), 0) + 1
            active_queries[host] = active_queries.get(host, 0) + 1
            peak_active_hosts = max(peak_active_hosts, len(active_queries))
            await asyncio.sleep(0)
            active_queries[host] -= 1
            if not active_queries[host]:
                del active_queries[host]
            if record_type == 'A':
                record = SimpleNamespace(data=SimpleNamespace(addr='192.0.2.10'))
                return SimpleNamespace(answer=[record])
            raise hostchecker.aiodns.error.DNSError(hostchecker.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    candidates = [f'host-{index}.example.com' for index in range(5)]
    checker = hostchecker.Checker(
        [*candidates, 'HOST-0.EXAMPLE.COM.'],
        nameservers=[],
        concurrency=2,
    )

    resolved, hosts, addresses = await checker.check()

    assert hosts == candidates
    assert resolved == [f'{host}:192.0.2.10' for host in candidates]
    assert addresses == ['192.0.2.10']
    assert query_counts == {(host, record_type): 1 for host in candidates for record_type in ('A', 'AAAA', 'CNAME')}
    assert peak_active_hosts == checker.concurrency
    assert closed


@pytest.mark.asyncio
async def test_check_default_limits_process_more_than_former_query_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        async def query_dns(self, host: str, record_type: str):
            if record_type == 'A':
                return SimpleNamespace(answer=[SimpleNamespace(data=SimpleNamespace(addr='192.0.2.10'))])
            raise hostchecker.aiodns.error.DNSError(hostchecker.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            return None

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker([f'host-{index}.example.com' for index in range(1_001)], nameservers=[])

    _resolved, hosts, _addresses = await checker.check()

    assert len(hosts) == checker.completed_count == 1_001
    assert checker.request_count == 3_003
    assert checker.stop_reason is None


@pytest.mark.parametrize(
    ('option', 'value', 'message'),
    [
        ('concurrency', True, 'DNS concurrency must be a positive integer'),
        ('concurrency', 0, 'DNS concurrency must be a positive integer'),
        ('request_limit', False, 'DNS request limit must be a positive integer'),
        ('request_limit', 1.5, 'DNS request limit must be a positive integer'),
        ('runtime_seconds', True, 'DNS runtime must be a positive finite number'),
        ('runtime_seconds', float('inf'), 'DNS runtime must be a positive finite number'),
    ],
)
def test_checker_rejects_invalid_finite_limits(option: str, value: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        hostchecker.Checker(['one.example.com'], [], **{option: value})


@pytest.mark.asyncio
async def test_check_stops_at_record_query_budget_and_retains_completed_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queried: list[tuple[str, str]] = []

    class FakeResolver:
        async def query_dns(self, host: str, record_type: str):
            queried.append((host, record_type))
            if record_type == 'A':
                record = SimpleNamespace(data=SimpleNamespace(addr='192.0.2.10'))
                return SimpleNamespace(answer=[record])
            raise hostchecker.aiodns.error.DNSError(hostchecker.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            return None

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(
        ['one.example.com', 'two.example.com'],
        nameservers=[],
        concurrency=1,
        request_limit=3,
    )

    assert await checker.check() == (
        ['one.example.com:192.0.2.10'],
        ['one.example.com'],
        ['192.0.2.10'],
    )
    assert queried == [
        ('one.example.com', 'A'),
        ('one.example.com', 'AAAA'),
        ('one.example.com', 'CNAME'),
    ]
    assert checker.request_count == 3
    assert checker.completed_count == 1
    assert checker.stop_reason == 'query-limit'


@pytest.mark.asyncio
async def test_check_runtime_limit_retains_completed_results_and_closes_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = False

    class FakeResolver:
        async def query_dns(self, host: str, record_type: str):
            if host == 'two.example.com':
                await asyncio.Event().wait()
            if record_type == 'A':
                record = SimpleNamespace(data=SimpleNamespace(addr='192.0.2.10'))
                return SimpleNamespace(answer=[record])
            raise hostchecker.aiodns.error.DNSError(hostchecker.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(
        ['one.example.com', 'two.example.com'],
        nameservers=[],
        concurrency=1,
        runtime_seconds=0.01,
    )

    assert await checker.check() == (
        ['one.example.com:192.0.2.10'],
        ['one.example.com'],
        ['192.0.2.10'],
    )
    assert checker.request_count == 6
    assert checker.completed_count == 1
    assert checker.stop_reason == 'runtime-limit'
    assert closed


@pytest.mark.asyncio
async def test_check_cancellation_closes_resolver_before_propagating(monkeypatch: pytest.MonkeyPatch) -> None:
    started = asyncio.Event()
    closed = False

    class FakeResolver:
        async def query_dns(self, _host: str, _record_type: str):
            started.set()
            await asyncio.Event().wait()

        async def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['one.example.com'], nameservers=[])
    task = asyncio.create_task(checker.check())
    await started.wait()

    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert closed


@pytest.mark.asyncio
async def test_check_repeated_cancellation_finishes_close_and_preserves_first_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    query_started = asyncio.Event()
    close_started = asyncio.Event()
    close_release = asyncio.Event()
    closed = asyncio.Event()

    class FakeResolver:
        async def query_dns(self, _host: str, _record_type: str):
            query_started.set()
            await asyncio.Event().wait()

        async def close(self) -> None:
            close_started.set()
            await close_release.wait()
            closed.set()

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['one.example.com'], nameservers=[])
    task = asyncio.create_task(checker.check())
    await query_started.wait()
    task.cancel('dns-query-cancelled')
    await close_started.wait()

    task.cancel('operator-stop-again')
    await asyncio.sleep(0)
    close_release.set()

    with pytest.raises(asyncio.CancelledError) as raised:
        await task
    assert raised.value.args == ('dns-query-cancelled',)
    assert closed.is_set()


@pytest.mark.asyncio
async def test_check_retains_a_record_and_excludes_missing_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        async def query_dns(self, host: str, record_type: str):
            if host == 'missing.example.com' or record_type != 'A':
                raise OSError('not found')
            record = SimpleNamespace(data=SimpleNamespace(addr='192.0.2.10'))
            return SimpleNamespace(answer=[record])

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['found.example.com', 'missing.example.com'], nameservers=[])

    resolved, hosts, addresses = await checker.check()

    assert resolved == ['found.example.com:192.0.2.10']
    assert hosts == ['found.example.com']
    assert addresses == ['192.0.2.10']
    assert checker.records['found.example.com'].ipv4 == ('192.0.2.10',)


@pytest.mark.asyncio
async def test_check_retains_aaaa_only_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        async def query_dns(self, _host: str, record_type: str):
            if record_type == 'AAAA':
                record = SimpleNamespace(data=SimpleNamespace(addr='2001:0db8::10'))
                return SimpleNamespace(answer=[record])
            raise OSError('no data')

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['ipv6.example.com'], nameservers=[])

    resolved, hosts, addresses = await checker.check()

    assert resolved == ['ipv6.example.com:2001:db8::10']
    assert hosts == ['ipv6.example.com']
    assert addresses == ['2001:db8::10']
    assert checker.records['ipv6.example.com'].ipv6 == ('2001:db8::10',)


@pytest.mark.asyncio
async def test_check_retains_cname_only_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        async def query_dns(self, _host: str, record_type: str):
            if record_type == 'CNAME':
                record = SimpleNamespace(data=SimpleNamespace(cname='Target.Example.NET.'))
                return SimpleNamespace(answer=[record])
            raise OSError('no data')

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['alias.example.com'], nameservers=[])

    resolved, hosts, addresses = await checker.check()

    assert resolved == ['alias.example.com']
    assert hosts == ['alias.example.com']
    assert addresses == []
    assert checker.records['alias.example.com'].cnames == ('target.example.net',)


@pytest.mark.asyncio
async def test_dns_force_preserves_legacy_result_and_typed_records(monkeypatch: pytest.MonkeyPatch) -> None:
    records = {'www.example.com': hostchecker.HostDnsRecords(ipv4=('192.0.2.10',))}

    class FakeChecker:
        def __init__(self, _hosts: list[str], nameservers: list[str], **_kwargs: object) -> None:
            assert nameservers == ['192.0.2.53']
            self.records = records
            self.query_error_count = 2
            self.query_error_types = {'TimeoutError'}

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['www.example.com:192.0.2.10'], ['www.example.com'], ['192.0.2.10']

    monkeypatch.setattr(dnssearch.hostchecker, 'Checker', FakeChecker)
    dns_force = dnssearch.DnsForce('example.com', ['192.0.2.53'])
    dns_force.list = ['www.example.com']

    result = await dns_force.run()

    assert result == (['www.example.com:192.0.2.10'], ['www.example.com'], ['192.0.2.10'])
    assert dns_force.records is records
    assert dns_force.query_error_count == 2
    assert dns_force.query_error_types == {'TimeoutError'}


@pytest.mark.asyncio
async def test_dns_force_admits_every_candidate_without_source_validation_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admitted: list[str] = []

    class FakeChecker:
        records: ClassVar[dict[str, hostchecker.HostDnsRecords]] = {}
        query_error_count = 0
        query_error_types: ClassVar[set[str]] = set()

        def __init__(
            self,
            hosts: list[str],
            nameservers: list[str],
            *,
            concurrency: int,
            request_limit: int | None,
            runtime_seconds: float | None,
        ) -> None:
            assert nameservers == ['192.0.2.53']
            assert concurrency == 50
            assert request_limit is None
            assert runtime_seconds is None
            self.completed_count = len(hosts)
            self.stop_reason = None
            admitted.extend(hosts)

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return [], [], []

    monkeypatch.setattr(dnssearch.hostchecker, 'Checker', FakeChecker)
    dns_force = dnssearch.DnsForce('example.com', ['192.0.2.53'])

    assert len(dns_force.list) > 1_000
    assert await dns_force.run() == ([], [], [])
    assert admitted == dns_force.list
    assert dns_force.completed_count == len(dns_force.list)
    assert dns_force.stop_reason is None


def test_dns_force_preserves_selected_www_target() -> None:
    dns_force = dnssearch.DnsForce('www.example.com', ['192.0.2.53'])

    assert dns_force.domain == 'www.example.com'
    assert all(candidate.endswith('.www.example.com') for candidate in dns_force.list)


@pytest.mark.asyncio
async def test_check_normalizes_and_deduplicates_mixed_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        'A': [('addr', '192.0.2.10'), ('addr', '192.0.2.10'), ('addr', '999.0.0.1')],
        'AAAA': [('addr', '2001:0db8::10'), ('addr', '2001:db8:0:0::10')],
        'CNAME': [('cname', 'Target.Example.NET.'), ('cname', 'target.example.net')],
    }

    class FakeResolver:
        async def query_dns(self, _host: str, record_type: str):
            records = [SimpleNamespace(data=SimpleNamespace(**{field: value})) for field, value in values[record_type]]
            return SimpleNamespace(answer=records)

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['mixed.example.com'], nameservers=[])

    resolved, hosts, addresses = await checker.check()

    assert resolved == ['mixed.example.com:192.0.2.10,2001:db8::10']
    assert hosts == ['mixed.example.com']
    assert addresses == ['192.0.2.10', '2001:db8::10']
    assert checker.records['mixed.example.com'] == hostchecker.HostDnsRecords(
        ipv4=('192.0.2.10',),
        ipv6=('2001:db8::10',),
        cnames=('target.example.net',),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'outcome',
    [
        hostchecker.aiodns.error.DNSError(hostchecker.aiodns.error.ARES_ENOTFOUND, 'not found'),
        hostchecker.aiodns.error.DNSError(hostchecker.aiodns.error.ARES_ENODATA, 'no data'),
        SimpleNamespace(answer=[]),
        OSError('resolver error'),
        TimeoutError('timed out'),
    ],
)
async def test_check_excludes_candidate_without_usable_evidence(
    monkeypatch: pytest.MonkeyPatch,
    outcome: object,
) -> None:
    class FakeResolver:
        async def query_dns(self, _host: str, _record_type: str):
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['missing.example.com'], nameservers=[])

    assert await checker.check() == ([], [], [])
    assert checker.records == {}


@pytest.mark.asyncio
async def test_check_distinguishes_expected_absence_from_query_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    not_found = hostchecker.aiodns.error.DNSError(hostchecker.aiodns.error.ARES_ENOTFOUND, 'not found')
    no_data = hostchecker.aiodns.error.DNSError(hostchecker.aiodns.error.ARES_ENODATA, 'no data')

    class FakeResolver:
        async def query_dns(self, host: str, _record_type: str):
            if host == 'missing.example.com':
                raise not_found
            if host == 'empty.example.com':
                raise no_data
            raise TimeoutError('resolver timed out')

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(
        ['missing.example.com', 'empty.example.com', 'timeout.example.com'],
        nameservers=[],
    )

    assert await checker.check() == ([], [], [])
    assert checker.query_error_count == 3
    assert checker.query_error_types == {'TimeoutError'}


@pytest.mark.asyncio
async def test_dns_force_defaults_diagnostics_for_existing_checker_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    class ExistingChecker:
        records: ClassVar[dict[str, hostchecker.HostDnsRecords]] = {}

        def __init__(self, _hosts: list[str], nameservers: list[str], **_kwargs: object) -> None:
            assert nameservers == []

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return [], [], []

    monkeypatch.setattr(dnssearch.hostchecker, 'Checker', ExistingChecker)
    dns_force = dnssearch.DnsForce('example.com', [])
    dns_force.list = []

    assert await dns_force.run() == ([], [], [])
    assert dns_force.query_error_count == 0
    assert dns_force.query_error_types == set()


@pytest.mark.asyncio
async def test_reverse_single_ip_keeps_transport_failures_as_empty_results() -> None:
    class FakeResolver:
        async def gethostbyaddr(self, _ip: str):
            raise TimeoutError('resolver timed out')

    assert await dnssearch.reverse_single_ip('192.0.2.10', FakeResolver()) == ''


@pytest.mark.asyncio
async def test_reverse_range_reports_only_unexpected_ptr_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    not_found = hostchecker.aiodns.error.DNSError(hostchecker.aiodns.error.ARES_ENOTFOUND, 'not found')

    class FakeResolver:
        async def gethostbyaddr(self, ip: str):
            if ip == '192.0.2.1':
                return SimpleNamespace(name='api.example.com')
            if ip == '192.0.2.2':
                raise not_found
            raise TimeoutError('resolver timed out')

    monkeypatch.setattr(dnssearch, 'iter_ips_in_network_range', lambda _range: iter(['192.0.2.1', '192.0.2.2', '192.0.2.3']))
    monkeypatch.setattr(dnssearch, 'DNSResolver', lambda **_kwargs: FakeResolver())
    monkeypatch.setattr(dnssearch, 'log_query', lambda _ip: None)
    results: list[str] = []
    error_types: set[str] = set()

    await dnssearch.reverse_all_ips_in_range(
        '192.0.2.0/24',
        results.append,
        error_types=error_types,
    )

    assert results == ['api.example.com', '', '']
    assert error_types == {'TimeoutError'}


@pytest.mark.asyncio
async def test_reverse_ranges_deduplicate_ips_and_bound_one_global_job_set(monkeypatch: pytest.MonkeyPatch) -> None:
    queried: list[str] = []
    active = 0
    peak = 0
    closed = False

    class FakeResolver:
        async def gethostbyaddr(self, ip: str):
            nonlocal active, peak
            queried.append(ip)
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0)
            active -= 1
            return SimpleNamespace(name=f'host-{ip}.example.com')

        async def close(self) -> None:
            nonlocal closed
            closed = True

    ranges = {
        '192.0.2.0/24': ['192.0.2.1', '192.0.2.2'],
        '192.0.2.128/25': ['192.0.2.2', '192.0.2.3'],
    }
    monkeypatch.setattr(dnssearch, 'iter_ips_in_network_range', lambda iprange: iter(ranges[iprange]))
    monkeypatch.setattr(dnssearch, 'DNSResolver', lambda **_kwargs: FakeResolver())
    monkeypatch.setattr(dnssearch, 'log_query', lambda _ip: None)
    found: list[str] = []

    result = await dnssearch.reverse_ip_ranges(
        tuple(ranges),
        found.append,
        concurrency=2,
    )

    assert sorted(queried) == ['192.0.2.1', '192.0.2.2', '192.0.2.3']
    assert sorted(found) == [
        'host-192.0.2.1.example.com',
        'host-192.0.2.2.example.com',
        'host-192.0.2.3.example.com',
    ]
    assert peak == 2
    assert result.request_count == 3
    assert result.completed_count == 3
    assert result.stop_reason is None
    assert closed


@pytest.mark.asyncio
async def test_reverse_ranges_stop_at_query_budget_with_partial_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        async def gethostbyaddr(self, ip: str):
            return SimpleNamespace(name=f'host-{ip}.example.com')

        async def close(self) -> None:
            return None

    monkeypatch.setattr(
        dnssearch,
        'iter_ips_in_network_range',
        lambda _range: iter(['192.0.2.1', '192.0.2.2']),
    )
    monkeypatch.setattr(dnssearch, 'DNSResolver', lambda **_kwargs: FakeResolver())
    monkeypatch.setattr(dnssearch, 'log_query', lambda _ip: None)
    found: list[str] = []

    result = await dnssearch.reverse_ip_ranges(
        ('192.0.2.0/24',),
        found.append,
        concurrency=1,
        request_limit=1,
    )

    assert found == ['host-192.0.2.1.example.com']
    assert result.request_count == 1
    assert result.completed_count == 1
    assert result.stop_reason == 'query-limit'


@pytest.mark.asyncio
async def test_reverse_defaults_process_more_than_former_candidate_ceiling_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        async def gethostbyaddr(self, _ip: str):
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr(
        dnssearch,
        'iter_ips_in_network_range',
        lambda _range: (f'192.0.{index // 255}.{index % 255}' for index in range(1, 3_002)),
    )
    monkeypatch.setattr(dnssearch, 'DNSResolver', lambda **_kwargs: FakeResolver())
    monkeypatch.setattr(dnssearch, 'log_query', lambda _ip: None)

    result = await dnssearch.reverse_ip_ranges(('large-range',), lambda _host: None)

    assert result == dnssearch.ReverseDNSResult(3_001, 3_001)


@pytest.mark.asyncio
async def test_reverse_ranges_stop_materializing_after_the_finite_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    generated = 0

    def many_addresses(_range: str):
        nonlocal generated
        for index in range(1, 10_001):
            generated += 1
            yield f'192.0.{index // 255}.{index % 255}'

    class FakeResolver:
        async def gethostbyaddr(self, _ip: str):
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr(dnssearch, 'iter_ips_in_network_range', many_addresses)
    monkeypatch.setattr(dnssearch, 'DNSResolver', lambda **_kwargs: FakeResolver())
    monkeypatch.setattr(dnssearch, 'log_query', lambda _ip: None)

    result = await dnssearch.reverse_ip_ranges(
        ('large-range',),
        lambda _host: None,
        request_limit=3,
    )

    assert generated == 4
    assert result.request_count == 3
    assert result.completed_count == 3
    assert result.stop_reason == 'query-limit'


@pytest.mark.asyncio
async def test_reverse_large_real_range_stays_bounded_before_the_request_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResolver:
        async def gethostbyaddr(self, _ip: str):
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr(dnssearch, 'DNSResolver', lambda **_kwargs: FakeResolver())
    monkeypatch.setattr(dnssearch, 'log_query', lambda _ip: None)
    tracemalloc.start()
    baseline, _peak = tracemalloc.get_traced_memory()
    try:
        result = await dnssearch.reverse_ip_ranges(
            ('10.0.0.0/16',),
            lambda _host: None,
            request_limit=3,
        )
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert result == dnssearch.ReverseDNSResult(3, 3, 'query-limit')
    assert peak - baseline < 1_000_000


@pytest.mark.asyncio
async def test_reverse_ranges_propagate_resolver_close_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        async def gethostbyaddr(self, _ip: str):
            return None

        async def close(self) -> None:
            raise asyncio.CancelledError('resolver-close-cancelled')

    monkeypatch.setattr(dnssearch, 'iter_ips_in_network_range', lambda _range: iter(['192.0.2.1']))
    monkeypatch.setattr(dnssearch, 'DNSResolver', lambda **_kwargs: FakeResolver())
    monkeypatch.setattr(dnssearch, 'log_query', lambda _ip: None)

    with pytest.raises(asyncio.CancelledError, match='reverse DNS resolver close cancelled'):
        await dnssearch.reverse_ip_ranges(('192.0.2.0/24',), lambda _host: None)


@pytest.mark.asyncio
async def test_reverse_ranges_external_repeated_cancellation_closes_resolver_and_preserves_first_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    query_started = asyncio.Event()
    close_started = asyncio.Event()
    close_release = asyncio.Event()
    closed = asyncio.Event()

    class FakeResolver:
        async def gethostbyaddr(self, _ip: str):
            query_started.set()
            await asyncio.Event().wait()

        async def close(self) -> None:
            close_started.set()
            await close_release.wait()
            closed.set()

    monkeypatch.setattr(dnssearch, 'iter_ips_in_network_range', lambda _range: iter(['192.0.2.1']))
    monkeypatch.setattr(dnssearch, 'DNSResolver', lambda **_kwargs: FakeResolver())
    monkeypatch.setattr(dnssearch, 'log_query', lambda _ip: None)
    task = asyncio.create_task(dnssearch.reverse_ip_ranges(('192.0.2.0/24',), lambda _host: None))
    await query_started.wait()
    task.cancel('ptr-query-cancelled')
    await close_started.wait()

    task.cancel('operator-stop-again')
    await asyncio.sleep(0)
    close_release.set()

    with pytest.raises(asyncio.CancelledError) as raised:
        await task
    assert raised.value.args == ('ptr-query-cancelled',)
    assert closed.is_set()


@pytest.mark.asyncio
async def test_check_propagates_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        async def query_dns(self, _host: str, _record_type: str):
            raise asyncio.CancelledError

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['cancelled.example.com'], nameservers=[])

    with pytest.raises(asyncio.CancelledError):
        await checker.check()


@pytest.mark.asyncio
async def test_check_rejects_address_record_type_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {'A': '2001:db8::10', 'AAAA': '192.0.2.10'}

    class FakeResolver:
        async def query_dns(self, _host: str, record_type: str):
            if record_type == 'CNAME':
                raise OSError('no data')
            record = SimpleNamespace(data=SimpleNamespace(addr=values[record_type]))
            return SimpleNamespace(answer=[record])

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['mismatch.example.com'], nameservers=[])

    assert await checker.check() == ([], [], [])


@pytest.mark.asyncio
async def test_check_rejects_empty_cname(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        async def query_dns(self, _host: str, record_type: str):
            if record_type == 'CNAME':
                record = SimpleNamespace(data=SimpleNamespace(cname='.'))
                return SimpleNamespace(answer=[record])
            raise OSError('no data')

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', lambda **_kwargs: FakeResolver())
    checker = hostchecker.Checker(['empty.example.com'], nameservers=[])

    assert await checker.check() == ([], [], [])
