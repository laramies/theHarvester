import json
import socket
import sys
import xml.etree.ElementTree as ElementTree
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import UUID

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.lib.source_catalog import SOURCE_SPECS, ActivityClass

NON_PASSIVE_SOURCES = (
    'criminalip',
    'pentesttools',
    'shodan',
    'shodanInternetDB',
    'subdomainfinderc99',
    'windvane',
)


@pytest.mark.asyncio
async def test_source_help_uses_the_runtime_catalog(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(theharvester_main, 'SOURCE_SPECS', {'catalog-only-source': object()})
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '--help'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    help_output = capsys.readouterr().out
    assert 'catalog-only-source' in help_output
    assert 'linkedin_links' not in help_output


@pytest.mark.asyncio
async def test_activity_summary_includes_source_and_option_classes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args: object) -> None:
            return None

        async def save_run(self, _result: object) -> None:
            return None

    class FakeCriminalIP:
        def __init__(self, _domain: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_ips(self) -> set[str]:
            return set()

        async def get_asns(self) -> set[str]:
            return set()

    monkeypatch.setattr(theharvester_main.criminalip, 'SearchCriminalIP', FakeCriminalIP)
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.test', '-b', 'criminalip', '-n', '-s'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert '[*] Activity: P0 passive collection, P1 DNS interaction, P2 direct interaction' in capsys.readouterr().out


@pytest.mark.asyncio
async def test_activity_summary_covers_api_scan_without_sources(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args: object) -> None:
            return None

        async def save_run(self, _result: object) -> None:
            return None

    def stop_api_scan(**_kwargs: object) -> None:
        raise RuntimeError('offline test stop')

    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', stop_api_scan)
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.test', '-a'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert '[*] Activity: P2 direct interaction' in capsys.readouterr().out


@pytest.mark.asyncio
async def test_legacy_handlerless_source_does_not_break_activity_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def save_run(self, _result: object) -> None:
            return None

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.test', '-b', 'linkedin'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('source', NON_PASSIVE_SOURCES)
async def test_explicit_non_passive_source_is_scheduled_once(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    executions = 0

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args: object) -> None:
            return None

        async def save_run(self, *_args: object) -> None:
            return None

    class FakeAdapter:
        async def process(self, *_args: object, **_kwargs: object) -> None:
            nonlocal executions
            executions += 1

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_emails(self) -> set[str]:
            return set()

        async def get_ips(self) -> set[str]:
            return set()

        async def get_asns(self) -> set[str]:
            return set()

    if source == 'shodan':

        class FakeShodan:
            async def search_ip(self, _ip: str) -> dict:
                nonlocal executions
                executions += 1
                return {}

        monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', FakeShodan)
        monkeypatch.setattr(socket, 'gethostbyname', lambda _domain: '203.0.113.1')
    else:
        module, constructor_name = {
            'criminalip': (theharvester_main.criminalip, 'SearchCriminalIP'),
            'pentesttools': (theharvester_main.pentesttools, 'SearchPentestTools'),
            'shodanInternetDB': (theharvester_main.shodan_internetdb, 'SearchShodanInternetDB'),
            'subdomainfinderc99': (theharvester_main.subdomainfinderc99, 'SearchSubdomainfinderc99'),
            'windvane': (theharvester_main.windvane, 'SearchWindvane'),
        }[source]
        monkeypatch.setattr(module, constructor_name, lambda *_args, **_kwargs: FakeAdapter())

    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.test', '-b', source])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert executions == 1


@pytest.mark.asyncio
async def test_all_schedules_each_passive_catalog_source_once_and_reports_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executions: Counter[str] = Counter()
    passive_sources = sorted(source for source, spec in SOURCE_SPECS.items() if spec.activity is ActivityClass.PASSIVE)

    class TestResultStore(theharvester_main.ResultStore):
        def __init__(self) -> None:
            super().__init__(tmp_path / 'stash.sqlite')

        async def record_observations(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    class FakeAdapter:
        def __init__(self, adapter: str) -> None:
            self.adapter = adapter

        async def process(self, *_args: object, **_kwargs: object) -> None:
            executions[self.adapter] += 1

        async def get_hostnames(self) -> set[str]:
            return {'sub.example.test'}

        async def get_emails(self) -> set[str]:
            return {'user@example.test'}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.1'}

        async def get_asns(self) -> set[str]:
            return {'AS64500'}

        async def get_people(self) -> list[dict[str, str]]:
            return [{'name': 'Example Person'}]

        async def get_urls(self) -> set[str]:
            return {'https://sub.example.test/evidence'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return set()

        async def get_breach_names(self) -> set[str]:
            return {'ExampleBreach'}

        async def get_infostealers(self) -> list[dict[str, object]]:
            return []

    def fake_constructor(adapter: str):
        def constructor(*_args: object, **_kwargs: object) -> FakeAdapter:
            return FakeAdapter(adapter)

        return constructor

    discovery_modules = sorted(
        {
            value
            for value in vars(theharvester_main).values()
            if isinstance(value, ModuleType) and value.__name__.startswith('theHarvester.discovery.')
        },
        key=lambda module: module.__name__,
    )
    patched_classes = 0
    for module in discovery_modules:
        for name, value in list(vars(module).items()):
            if isinstance(value, type) and value.__module__ == module.__name__:
                monkeypatch.setattr(module, name, fake_constructor(f'{module.__name__}.{name}'))
                patched_classes += 1
    assert patched_classes

    report = tmp_path / 'all-sources'
    monkeypatch.setattr(theharvester_main, 'ResultStore', TestResultStore)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.test', '-b', 'all', '-f', str(report)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert len(executions) == len(passive_sources)
    assert sum(executions.values()) == len(passive_sources)
    assert set(executions.values()) == {1}

    json_report = json.loads(report.with_suffix('.json').read_text())
    assert 'sub.example.test' in json_report['hosts']
    assert 'user@example.test' in json_report['emails']
    assert json_report['urls'] == ['https://sub.example.test/evidence']
    assert not {'interesting_urls', 'linkedin_links', 'trello_urls'} & json_report.keys()

    jsonl_records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    findings = {(record['type'], record['value']): record for record in jsonl_records[1:]}
    assert findings[('hostname', 'sub.example.test')]['sources']
    assert findings[('email', 'user@example.test')]['sources']
    assert findings[('url', 'https://sub.example.test/evidence')]['sources'] == [
        'bevigil',
        'builtwith',
        'gitlab',
        'intelx',
        'rocketreach',
        'urlscan',
        'zoomeye',
    ]

    completed = await TestResultStore().load_run(UUID(jsonl_records[0]['run_id']))
    assert completed.target == 'example.test'
    assert ('hostname', 'sub.example.test') in completed.results
    assert ('email', 'user@example.test') in completed.results
    assert ('ip-address', '192.0.2.1') in completed.results

    xml_hosts = {
        (element.findtext('hostname') or (element.text or '').strip())
        for element in ElementTree.parse(report.with_suffix('.xml')).getroot().findall('host')
    }
    assert 'sub.example.test' in xml_hosts
