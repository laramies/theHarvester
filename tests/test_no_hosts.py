from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ElementTree
from typing import TYPE_CHECKING

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.lib import source_runner
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.enumeration import EnumerationOptions

if TYPE_CHECKING:
    from pathlib import Path


class NoopResultStore:
    async def initialize(self) -> None:
        return None

    async def save_run(self, _result: CompletedResult) -> None:
        return None


class MixedResultSource:
    async def process(self, _proxy: bool) -> None:
        return None

    async def get_hostnames(self) -> list[str]:
        raise AssertionError('hostname results must not be retrieved')

    async def get_ips(self) -> list[str]:
        return ['192.0.2.10']


@pytest.mark.parametrize(
    ('overrides', 'option'),
    [
        ({'shodan': True}, '--shodan'),
        ({'dns_resolve': None}, '--dns-resolve'),
        ({'dns_lookup': True}, '--dns-lookup'),
        ({'dns_brute': True}, '--dns-brute'),
        ({'dns_recursive_depth': 1}, '--dns-recursive-depth'),
        ({'take_over': True}, '--take-over'),
        ({'screenshot': 'screenshots'}, '--screenshot'),
        ({'vhost': True}, '--vhost'),
    ],
)
@pytest.mark.asyncio
async def test_no_hosts_rejects_hostname_dependent_cli_actions(
    overrides: dict[str, object],
    option: str,
) -> None:
    with pytest.raises(ValueError, match=rf'--no-hosts cannot be combined with: {option}'):
        await theharvester_main.start(
            EnumerationOptions(
                domain='example.com',
                source='bufferoverun',
                no_hosts=True,
                quiet=True,
                **overrides,
            )
        )


@pytest.mark.asyncio
async def test_no_hosts_keeps_mixed_source_ip_without_retrieving_hostnames(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(theharvester_main, 'ResultStore', NoopResultStore)
    monkeypatch.setattr(source_runner.bufferoverun, 'SearchBufferover', lambda _word: MixedResultSource())

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='bufferoverun', no_hosts=True, quiet=True),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    assert completed.results == (('ip', '192.0.2.10'),)
    assert completed.observations[0].source == 'bufferoverun'
    assert completed.source_executions[0].status == 'completed'
    assert completed.source_executions[0].result_count == 1
    assert response[-2] == []


@pytest.mark.asyncio
async def test_no_hosts_skips_host_only_source_before_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    class HostOnlySource:
        def __init__(self, _word: str) -> None:
            raise AssertionError('host-only source must not be constructed')

    monkeypatch.setattr(theharvester_main, 'ResultStore', NoopResultStore)
    monkeypatch.setattr(source_runner.crtsh, 'SearchCrtsh', HostOnlySource)

    response = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='crtsh', no_hosts=True, quiet=True),
        return_completed_result=True,
    )

    completed = response[-1]
    assert isinstance(completed, CompletedResult)
    assert completed.results == ()
    assert completed.source_executions[0].source == 'crtsh'
    assert completed.source_executions[0].status == 'skipped'
    assert completed.source_executions[0].stop_reason == 'hostname-collection-disabled'


@pytest.mark.asyncio
async def test_no_hosts_omits_hostname_records_from_every_file_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / 'non-host-results'
    monkeypatch.setattr(theharvester_main, 'ResultStore', NoopResultStore)
    monkeypatch.setattr(source_runner.bufferoverun, 'SearchBufferover', lambda _word: MixedResultSource())
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'bufferoverun', '--no-hosts', '-f', str(output)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    legacy_json = json.loads(output.with_suffix('.json').read_text(encoding='utf-8'))
    assert legacy_json['ips'] == ['192.0.2.10']
    assert 'hosts' not in legacy_json
    assert 'vhosts' not in legacy_json
    xml_root = ElementTree.parse(output.with_suffix('.xml')).getroot()
    assert xml_root.findall('host') == []
    assert xml_root.findall('vhost') == []
    jsonl = [json.loads(line) for line in output.with_suffix('.jsonl').read_text(encoding='utf-8').splitlines()]
    assert [item['type'] for item in jsonl[1:]] == ['ip']
