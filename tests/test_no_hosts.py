from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

from theHarvester import __main__
from theHarvester.lib.host_collection import (
    HostCollectionOptionError,
    enabled_host_dependent_options,
    should_collect_hosts,
    validate_host_collection_options,
)


class FakeStashManager:
    stored_types: list[str] = []

    async def do_init(self) -> None:
        return None

    async def store_all(self, _domain: str, _values: list, result_type: str, _source: str) -> None:
        self.stored_types.append(result_type)

    async def store(self, _domain: str, _value: str, result_type: str, _source: str) -> None:
        self.stored_types.append(result_type)


class FakeDuckDuckGoSearch:
    hostnames_requested = False
    emails_requested = False

    def __init__(self, _domain: str, _limit: int) -> None:
        pass

    async def process(self, _proxy: bool) -> None:
        return None

    async def get_hostnames(self) -> list[str]:
        self.__class__.hostnames_requested = True
        return ['portal.example.com']

    async def get_emails(self) -> list[str]:
        self.__class__.emails_requested = True
        return ['security@example.com']


class FakeDymoSearch:
    process_called = False

    def __init__(self, _domain: str) -> None:
        pass

    async def process(self, _proxy: bool) -> None:
        self.__class__.process_called = True

    async def get_hostnames(self) -> list[str]:
        return ['portal.example.com']


class FakeBufferOverSearch:
    hostnames_requested = False
    ips_requested = False

    def __init__(self, _domain: str) -> None:
        pass

    async def process(self, _proxy: bool) -> None:
        return None

    async def get_hostnames(self) -> list[str]:
        self.__class__.hostnames_requested = True
        return ['portal.example.com']

    async def get_ips(self) -> list[str]:
        self.__class__.ips_requested = True
        return ['203.0.113.10']


def make_rest_args(**overrides) -> argparse.Namespace:
    values = {
        'api_scan': False,
        'dns_brute': False,
        'dns_lookup': False,
        'dns_resolve': '',
        'dns_server': '',
        'domain': 'example.com',
        'filename': '',
        'limit': 10,
        'no_hosts': True,
        'proxies': False,
        'quiet': True,
        'screenshot': '',
        'shodan': False,
        'source': 'duckduckgo',
        'start': 0,
        'take_over': False,
        'wordlist': '',
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def reset_fakes() -> None:
    FakeStashManager.stored_types.clear()
    FakeDuckDuckGoSearch.hostnames_requested = False
    FakeDuckDuckGoSearch.emails_requested = False
    FakeDymoSearch.process_called = False
    FakeBufferOverSearch.hostnames_requested = False
    FakeBufferOverSearch.ips_requested = False


def test_should_collect_hosts_defaults_to_enabled() -> None:
    assert should_collect_hosts(argparse.Namespace()) is True
    assert should_collect_hosts(argparse.Namespace(no_hosts=False)) is True
    assert should_collect_hosts(argparse.Namespace(no_hosts=True)) is False


@pytest.mark.parametrize(
    ('overrides', 'expected_option'),
    [
        ({'shodan': True}, '--shodan'),
        ({'dns_lookup': True}, '--dns-lookup'),
        ({'dns_brute': True}, '--dns-brute'),
        ({'take_over': True}, '--take-over'),
        ({'dns_resolve': None}, '--dns-resolve'),
        ({'dns_resolve': '1.1.1.1'}, '--dns-resolve'),
        ({'screenshot': 'screenshots'}, '--screenshot'),
    ],
)
def test_enabled_host_dependent_options(overrides: dict[str, object], expected_option: str) -> None:
    args = make_rest_args(**overrides)
    assert expected_option in enabled_host_dependent_options(args)


def test_validate_host_collection_options_lists_all_conflicts() -> None:
    args = make_rest_args(shodan=True, dns_lookup=True, screenshot='screenshots')

    with pytest.raises(HostCollectionOptionError) as error:
        validate_host_collection_options(args)

    message = str(error.value)
    assert '--no-hosts cannot be combined with:' in message
    assert '--shodan' in message
    assert '--dns-lookup' in message
    assert '--screenshot' in message


@pytest.mark.asyncio
async def test_no_hosts_keeps_emails_without_requesting_or_storing_hostnames(monkeypatch) -> None:
    reset_fakes()
    monkeypatch.setattr(__main__.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(__main__.duckduckgosearch, 'SearchDuckDuckGo', FakeDuckDuckGoSearch)

    result = await __main__.start(make_rest_args())

    assert result[-2] == ['security@example.com']
    assert result[-1] == []
    assert FakeDuckDuckGoSearch.emails_requested is True
    assert FakeDuckDuckGoSearch.hostnames_requested is False
    assert 'email' in FakeStashManager.stored_types
    assert 'host' not in FakeStashManager.stored_types


@pytest.mark.asyncio
async def test_no_hosts_preserves_direct_ip_results(monkeypatch) -> None:
    reset_fakes()
    monkeypatch.setattr(__main__.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(__main__.bufferoverun, 'SearchBufferover', FakeBufferOverSearch)

    result = await __main__.start(make_rest_args(source='bufferoverun'))

    assert result[-3] == ['203.0.113.10']
    assert result[-1] == []
    assert FakeBufferOverSearch.ips_requested is True
    assert FakeBufferOverSearch.hostnames_requested is False
    assert 'ip' in FakeStashManager.stored_types
    assert 'host' not in FakeStashManager.stored_types


@pytest.mark.asyncio
async def test_no_hosts_skips_host_only_sources(monkeypatch) -> None:
    reset_fakes()
    monkeypatch.setattr(__main__.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(__main__.dymosearch, 'SearchDymo', FakeDymoSearch)

    result = await __main__.start(make_rest_args(source='dymo'))

    assert result[-1] == []
    assert FakeDymoSearch.process_called is False
    assert 'host' not in FakeStashManager.stored_types


@pytest.mark.asyncio
async def test_no_hosts_omits_host_console_and_file_output(monkeypatch, tmp_path: Path, capsys) -> None:
    reset_fakes()
    monkeypatch.setattr(__main__.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(__main__.duckduckgosearch, 'SearchDuckDuckGo', FakeDuckDuckGoSearch)

    output_base = tmp_path / 'no-hosts-results'
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'duckduckgo',
            '--no-hosts',
            '-f',
            str(output_base),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await __main__.start()

    assert exit_info.value.code == 0
    console_output = capsys.readouterr().out
    assert 'Hosts found' not in console_output
    assert 'No hosts found' not in console_output

    json_output = json.loads(output_base.with_suffix('.json').read_text(encoding='utf-8'))
    xml_output = output_base.with_suffix('.xml').read_text(encoding='utf-8')

    assert json_output['emails'] == ['security@example.com']
    assert 'hosts' not in json_output
    assert '<host>' not in xml_output
    assert '<hostname>' not in xml_output
    assert FakeDuckDuckGoSearch.hostnames_requested is False
