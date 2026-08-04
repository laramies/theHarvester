import asyncio
import json
import sys
import xml.etree.ElementTree as ElementTree
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

import theHarvester.__main__ as theharvester_main
from theHarvester.discovery import rapiddns
from theHarvester.lib.output import configure_logging

RAPID_DNS_HTML = """
<table><tbody>
  <tr><td>api.example.com</td><td>192.0.2.1</td><td>A</td></tr>
  <tr><td>broken.example.com</td><td>not-an-ip</td><td>A</td></tr>
  <tr><td>alias.example.com</td><td>target.example.net</td><td>CNAME</td></tr>
</tbody></table>
"""


async def fake_fetch_all(_urls: list[str], **_kwargs: Any) -> list[str]:
    await asyncio.sleep(0)
    return [RAPID_DNS_HTML]


@pytest.mark.asyncio
async def test_rapiddns_separates_hostnames_ips_and_associations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = rapiddns.SearchRapidDns('example.com')

    await search.process()

    hostnames = await search.get_hostnames()
    assert isinstance(hostnames, list)
    assert set(hostnames) == {
        'alias.example.com',
        'api.example.com',
        'broken.example.com',
    }
    assert await search.get_ips() == {'192.0.2.1'}
    assert await search.get_host_ip_pairs() == {('api.example.com', '192.0.2.1')}


@pytest.mark.asyncio
async def test_rapiddns_evidence_reaches_existing_outputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    stored: list[tuple[str, tuple[str, ...], str]] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, _domain: str, values: list[str], result_type: str, source: str) -> None:
            stored.append((result_type, tuple(sorted(values)), source))

        async def store(self, _domain: str, value: str, result_type: str, source: str) -> None:
            stored.append((result_type, (value,), source))

    class UnexpectedChecker:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError('DNS resolution requires the explicit --dns-resolve flag')

    class FakeDehashed:
        def __init__(self, _domain: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_ips(self) -> set[str]:
            return {'198.51.100.2'}

    report = tmp_path / 'rapiddns-report'
    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', UnexpectedChecker)
    monkeypatch.setattr(theharvester_main.search_dehashed, 'SearchDehashed', FakeDehashed)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'rapiddns', '-f', str(report)],
    )
    configure_logging(verbose=False)

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert stored == [
        ('host', ('alias.example.com', 'api.example.com', 'broken.example.com'), 'rapiddns'),
        ('ip', ('192.0.2.1',), 'rapiddns'),
    ]

    report_json = json.loads(report.with_suffix('.json').read_text())
    assert report_json['hosts'] == ['alias.example.com', 'api.example.com', 'broken.example.com']
    assert report_json['ips'] == ['192.0.2.1']

    xml_hosts = {
        (element.findtext('hostname') or (element.text or '').strip(), element.findtext('ip'))
        for element in ElementTree.parse(report.with_suffix('.xml')).getroot().findall('host')
    }
    assert xml_hosts == {
        ('alias.example.com', None),
        ('api.example.com', '192.0.2.1'),
        ('broken.example.com', None),
    }

    console = capsys.readouterr().out
    assert {'alias.example.com', 'api.example.com', 'broken.example.com', '192.0.2.1'} <= set(console.splitlines())

    rest_results = await theharvester_main.start(
        Namespace(
            source='dehashed,rapiddns',
            dns_brute=False,
            filename='',
            quiet=True,
            dns_lookup=False,
            dns_server=None,
            dns_resolve='',
            limit=500,
            shodan=False,
            start=0,
            domain='example.com',
            take_over=False,
            proxies=False,
        )
    )
    assert set(rest_results[6]) == {'192.0.2.1', '198.51.100.2'}
    assert rest_results[8] == ['alias.example.com', 'api.example.com', 'broken.example.com']
    assert stored[2:] == [
        ('ip', ('198.51.100.2',), 'dehashed'),
        ('host', ('alias.example.com', 'api.example.com', 'broken.example.com'), 'rapiddns'),
        ('ip', ('192.0.2.1',), 'rapiddns'),
    ]
