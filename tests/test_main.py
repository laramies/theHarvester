import json
import sys
from pathlib import Path

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.dns_consensus import Addressability
from theHarvester.lib.hostchecker import HostDnsRecords
from theHarvester.lib.recursive_dns import RecursiveDNSClassification, RecursiveDNSFinding, RecursiveDNSResult


@pytest.mark.parametrize('target', ['Example.COM.', 'WWW.Example.COM.'])
def test_normalize_hosts_for_storage_uses_the_parser_scope(target: str) -> None:
    discovered_hosts: set[object] = {
        'API.Example.COM.',
        'example.com',
        'badexample.com',
        'example.com.attacker.test',
        123,
    }

    assert theharvester_main._normalize_hosts_for_storage(discovered_hosts, target) == {'api.example.com'}


@pytest.mark.asyncio
async def test_rapiddns_hostnames_honor_explicit_dns_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    completed: list[CompletedResult] = []
    output_path = tmp_path / 'rapiddns'

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com', 'reported.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {('reported.example.com', '192.0.2.20')}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.20'}

    class FakeChecker:
        def __init__(self, hosts: list[str], nameservers: list[str]) -> None:
            assert hosts == ['api.example.com']
            assert nameservers == ['192.0.2.53']

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['api.example.com:192.0.2.10'], ['api.example.com'], ['192.0.2.10']

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)

    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'rapiddns',
            '-r',
            '192.0.2.53',
            '-f',
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert ('hostname', 'api.example.com') in completed[0].results
    assert ('hostname', 'reported.example.com') in completed[0].results
    assert ('ip-address', '192.0.2.10') in completed[0].results
    assert ('ip-address', '192.0.2.20') in completed[0].results
    assert 'reported.example.com' in json.loads(output_path.with_suffix('.json').read_text())['hosts']


@pytest.mark.asyncio
async def test_recursive_dns_requires_canonically_distinct_resolvers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '2001:db8::1,2001:0db8:0:0:0:0:0:1,192.0.2.53',
            '--dns-recursive-depth',
            '1',
        ],
    )

    with pytest.raises(ValueError, match='exactly three resolver vantages'):
        await theharvester_main.start()


@pytest.mark.asyncio
async def test_dns_proven_cname_hosts_reach_screenshot_filter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    visited: set[str] = set()

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

        async def store_completed_result(self, _result: CompletedResult) -> None:
            return None

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'address.example.com', 'alias.example.com', 'unresolved.example.com'}

    class FakeChecker:
        def __init__(self, hosts: list[str], _nameservers: list[str]) -> None:
            assert set(hosts) == {'address.example.com', 'alias.example.com', 'unresolved.example.com'}

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return (
                ['address.example.com:192.0.2.1', 'alias.example.com'],
                ['address.example.com', 'alias.example.com'],
                ['192.0.2.1'],
            )

    class FakeScreenShotter:
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            return None

        async def visit(self, host: str) -> tuple[str, str]:
            visited.add(host)
            return host, 'https'

        @staticmethod
        def chunk_list(values: list[str], _size: int) -> list[list[str]]:
            return [values]

        async def take_screenshot(self, host: str) -> tuple[str, str]:
            return host, f'{host}.png'

    class FakePool:
        def __init__(self, _workers: int) -> None:
            pass

        async def __aenter__(self) -> 'FakePool':
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def map(self, function, values):
            return [await function(value) for value in values]

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(theharvester_main, 'Pool', FakePool)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53',
            '--screenshot',
            str(tmp_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert visited == {'address.example.com', 'alias.example.com'}


@pytest.mark.asyncio
async def test_recursive_dns_results_reach_completed_output_without_changing_legacy_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed: list[CompletedResult] = []
    captured: list[tuple[str, tuple[str, ...], int, int]] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class FakeChecker:
        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            pass

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['api.example.com:192.0.2.1'], ['api.example.com'], ['192.0.2.1']

    class FakeResolver:
        def __init__(self, nameserver: str, target: str) -> None:
            self.name = nameserver
            assert target == 'example.com'

        async def close(self) -> None:
            return None

    async def fake_recursive(target, seeds, _labels, _resolvers, limits):
        captured.append((target, tuple(seeds), limits.depth, limits.query_limit))
        return RecursiveDNSResult(
            findings=(
                RecursiveDNSFinding(
                    'dev.api.example.com',
                    'api.example.com',
                    HostDnsRecords(ipv4=('192.0.2.2',)),
                    ('ptr.example.net',),
                ),
            ),
            query_count=24,
            depth_reached=1,
            zero_yield_batches=0,
            stop_reason='depth-limit',
            classifications=(
                RecursiveDNSClassification(
                    'unused.api.example.com',
                    'api.example.com',
                    Addressability.NOT_CURRENT,
                    HostDnsRecords(cnames=('missing.vendor.test',)),
                    ('legacy-ptr.example.net',),
                ),
            ),
        )

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main, 'AioDNSResolverVantage', FakeResolver)
    monkeypatch.setattr(theharvester_main, 'discover_recursive_dns', fake_recursive)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53,192.0.2.54,192.0.2.55',
            '--dns-recursive-depth',
            '1',
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert captured == [('example.com', ('api.example.com',), 1, 1_000)]
    assert completed
    assert ('hostname', 'dev.api.example.com') in completed[0].results
    assert ('ip-address', '192.0.2.2') in completed[0].results
    assert (
        'dns-recursive-finding',
        json.dumps(
            {
                'addresses': ['192.0.2.2'],
                'hostname': 'dev.api.example.com',
                'parent': 'api.example.com',
                'ptrs': ['ptr.example.net'],
            },
            separators=(',', ':'),
            sort_keys=True,
        ),
    ) in completed[0].results
    assert (
        'dns-recursive-summary',
        json.dumps(
            {'depth_reached': 1, 'query_count': 24, 'stop_reason': 'depth-limit', 'zero_yield_batches': 0},
            separators=(',', ':'),
            sort_keys=True,
        ),
    ) in completed[0].results
    assert (
        'dns-recursive-classification',
        json.dumps(
            {
                'addressability': 'not-currently-addressable',
                'addresses': [],
                'cnames': ['missing.vendor.test'],
                'hostname': 'unused.api.example.com',
                'parent': 'api.example.com',
                'ptrs': ['legacy-ptr.example.net'],
            },
            separators=(',', ':'),
            sort_keys=True,
        ),
    ) in completed[0].results
