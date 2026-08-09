import asyncio
from types import SimpleNamespace

import pytest

from theHarvester.discovery import dnssearch
from theHarvester.lib import hostchecker


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
        def __init__(self, _hosts: list[str], nameservers: list[str]) -> None:
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
        records: dict[str, hostchecker.HostDnsRecords] = {}

        def __init__(self, _hosts: list[str], nameservers: list[str]) -> None:
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

    monkeypatch.setattr(dnssearch, 'list_ips_in_network_range', lambda _range: ['192.0.2.1', '192.0.2.2', '192.0.2.3'])
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
