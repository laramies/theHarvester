import asyncio
import json
import logging
import sys
import xml.etree.ElementTree as ElementTree
from argparse import Namespace
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

import theHarvester.__main__ as theharvester_main
from theHarvester.discovery import rapiddns
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.core import FetcherResponse
from theHarvester.lib.output import configure_logging

RAPID_DNS_HTML = """
<table><tbody>
  <tr><td>api.example.com</td><td>192.0.2.1</td><td>A</td></tr>
  <tr><td>broken.example.com</td><td>not-an-ip</td><td>A</td></tr>
  <tr><td>alias.example.com</td><td>target.example.net</td><td>CNAME</td></tr>
</tbody></table>
"""


async def fake_fetch_all(_urls: list[str], **_kwargs: Any) -> list[FetcherResponse]:
    await asyncio.sleep(0)
    return [FetcherResponse(body=RAPID_DNS_HTML, status=200, headers={})]


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
@pytest.mark.parametrize('payload', ['', '<html><p>no results</p></html>'])
async def test_rapiddns_handles_empty_or_malformed_html(
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    async def fake_response(*_args: Any, **_kwargs: Any) -> list[FetcherResponse]:
        return [FetcherResponse(body=payload, status=200, headers={})]

    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch_all', fake_response)
    search = rapiddns.SearchRapidDns('example.com')

    await search.process()

    assert await search.get_hostnames() == []
    assert await search.get_ips() == set()
    assert await search.get_host_ip_pairs() == set()


@pytest.mark.asyncio
async def test_rapiddns_attributes_provider_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[str]:
        raise OSError('provider unavailable')

    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch_all', failed_fetch)
    search = rapiddns.SearchRapidDns('example.com')

    with caplog.at_level(logging.INFO, logger=rapiddns.__name__):
        await search.process()

    assert await search.get_hostnames() == []
    assert await search.get_ips() == set()
    assert 'RapidDNS error' in caplog.text


@pytest.mark.asyncio
async def test_rapiddns_attributes_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def rate_limited_fetch(*_args: Any, **kwargs: Any) -> list[FetcherResponse]:
        assert kwargs['include_metadata'] is True
        return [FetcherResponse(body='rate limited', status=429, headers={})]

    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch_all', rate_limited_fetch)
    search = rapiddns.SearchRapidDns('example.com')

    with caplog.at_level(logging.INFO, logger=rapiddns.__name__):
        await search.process()

    assert await search.get_hostnames() == []
    assert await search.get_ips() == set()
    assert 'RapidDNS request failed with HTTP 429' in caplog.text


@pytest.mark.asyncio
async def test_rapiddns_evidence_reaches_existing_outputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    stored: list[tuple[str, tuple[str, ...], str]] = []
    completed_results: list[CompletedResult] = []

    class FakeStash:
        fail_completed_write = False

        async def do_init(self) -> None:
            return None

        async def store_all(self, _domain: str, values: list[str], result_type: str, source: str) -> None:
            stored.append((result_type, tuple(sorted(values)), source))

        async def store(self, _domain: str, value: str, result_type: str, source: str) -> None:
            stored.append((result_type, (value,), source))

        async def store_completed_result(self, result: CompletedResult) -> None:
            if self.fail_completed_write:
                raise OSError('forced completed-result failure')
            completed_results.append(result)

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

    class FakeApiEndpoints:
        def __init__(self, *, word: str, wordlist: str) -> None:
            assert word == 'example.com'
            assert wordlist.endswith('api_endpoints.txt')

        async def do_search(self) -> None:
            return None

        def get_found_endpoints(self) -> dict[str, object]:
            return {'/health': object()}

        def get_interesting_endpoints(self) -> dict[str, object]:
            return {'/health': object()}

        def get_auth_required(self) -> dict[str, object]:
            return {}

        def get_api_versions(self) -> set[str]:
            return set()

        def get_rate_limits(self) -> dict[str, object]:
            return {}

        def get_methods(self) -> set[str]:
            return {'GET'}

        def get_status_codes(self) -> set[int]:
            return {200}

    class FakeSecurityScorecard:
        created = 0

        def __init__(self, _domain: str) -> None:
            self.is_late_action = self.created > 0
            type(self).created += 1

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_ips(self) -> set[str]:
            if self.is_late_action:
                return {'2001:0DB8::1', '198.51.100.9', 'not-an-ip'}
            return set()

    async def fake_reverse_all_ips_in_range(
        iprange: str,
        callback: Any,
        nameservers: list[str] | None = None,
    ) -> None:
        assert iprange in {'192.0.2.0/24', '198.51.100.0/24'}
        assert nameservers is None
        callback('reverse.example.com')

    report = tmp_path / 'rapiddns-report'
    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', UnexpectedChecker)
    monkeypatch.setattr(theharvester_main.search_dehashed, 'SearchDehashed', FakeDehashed)
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', FakeApiEndpoints)
    monkeypatch.setattr(theharvester_main.securityscorecard, 'SearchSecurityScorecard', FakeSecurityScorecard)
    monkeypatch.setattr(theharvester_main.dnssearch, 'reverse_all_ips_in_range', fake_reverse_all_ips_in_range)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'rapiddns,securityscorecard',
            '-a',
            '-n',
            '-f',
            str(report),
        ],
    )
    configure_logging(verbose=False)

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert ('host', ('alias.example.com', 'api.example.com', 'broken.example.com'), 'rapiddns') in stored
    assert ('ip', ('192.0.2.1',), 'rapiddns') in stored
    assert stored.count(('api_endpoint', ('/health',), 'api_scan')) == 2

    report_json = json.loads(report.with_suffix('.json').read_text())
    assert report_json['hosts'] == ['alias.example.com', 'api.example.com', 'broken.example.com']
    assert report_json['ips'] == ['192.0.2.1']
    assert 'interesting_urls' not in report_json

    jsonl_records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert jsonl_records[0]['type'] == 'summary'
    assert jsonl_records[0]['target'] == 'example.com'
    UUID(jsonl_records[0]['run_id'])
    assert [str(result.run_id) for result in completed_results] == [jsonl_records[0]['run_id']]
    assert {'type': 'interesting-url', 'value': 'https://example.com/health'} in jsonl_records
    assert {'type': 'url', 'value': 'https://example.com/health'} in jsonl_records
    assert {'type': 'hostname', 'value': 'reverse.example.com'} in jsonl_records
    assert {'type': 'ip-address', 'value': '198.51.100.9'} in jsonl_records
    assert {'type': 'ip-address', 'value': '2001:db8::1'} in jsonl_records
    assert not any(record.get('value') == 'not-an-ip' for record in jsonl_records)

    xml_hosts = {
        (element.findtext('hostname') or (element.text or '').strip(), element.findtext('ip'))
        for element in ElementTree.parse(report.with_suffix('.xml')).getroot().findall('host')
    }
    assert xml_hosts == {
        ('alias.example.com', None),
        ('api.example.com', '192.0.2.1'),
        ('broken.example.com', None),
        ('reverse.example.com', None),
    }

    console = capsys.readouterr().out
    assert {'alias.example.com', 'api.example.com', 'broken.example.com', '192.0.2.1'} <= set(console.splitlines())

    legacy_rest_results = await theharvester_main.start(
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
    stored_before_rest = len(stored)
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
            screenshot='',
            wordlist='',
            api_scan=False,
        ),
        persist_completed_result=True,
    )
    assert rest_results == legacy_rest_results
    assert set(rest_results[6]) == {'192.0.2.1', '198.51.100.2'}
    assert rest_results[8] == ['alias.example.com', 'api.example.com', 'broken.example.com']
    assert stored[stored_before_rest:] == [
        ('ip', ('198.51.100.2',), 'dehashed'),
        ('host', ('alias.example.com', 'api.example.com', 'broken.example.com'), 'rapiddns'),
        ('ip', ('192.0.2.1',), 'rapiddns'),
    ]
    assert len(completed_results) == 2
    assert FakeSecurityScorecard.created == 2
    assert completed_results[1].target == 'example.com'
    assert {'192.0.2.1', '198.51.100.2'} <= {value for kind, value in completed_results[1].results if kind == 'ip-address'}

    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'rapiddns'])
    with pytest.raises(SystemExit) as no_file_exit:
        await theharvester_main.start()
    assert no_file_exit.value.code == 0
    assert len(completed_results) == 3
    assert completed_results[2].target == 'example.com'

    FakeStash.fail_completed_write = True
    with pytest.raises(SystemExit) as failed_write_exit:
        await theharvester_main.start()
    assert failed_write_exit.value.code == 0
    assert len(completed_results) == 3
    assert 'forced completed-result failure' in capsys.readouterr().out
