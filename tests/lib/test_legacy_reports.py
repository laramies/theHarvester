from __future__ import annotations

import json

import pytest

from theHarvester.lib.legacy_reports import iter_xml_report, json_report, xml_report


def _json(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        'command_args': ['-d', 'example.test', '-b', 'crtsh,rapiddns'],
        'ips': [],
        'emails': [],
        'hosts': [],
        'virtual_hostnames': [],
        'urls': [],
        'asns': [],
        'prefixes': set(),
        'people': [],
        'takeover_results': {},
        'shodan': [],
    }
    values.update(overrides)
    return json.loads(json_report(**values))  # type: ignore[arg-type]


def test_json_report_keeps_required_keys_and_omits_empty_groups() -> None:
    assert _json() == {'cmd': '-d example.test -b crtsh,rapiddns', 'hosts': [], 'shodan': []}


def test_json_report_omits_hosts_and_vhosts_when_hostname_collection_is_disabled() -> None:
    assert _json(hosts=None, virtual_hostnames=['admin.example.test']) == {
        'cmd': '-d example.test -b crtsh,rapiddns',
        'shodan': [],
    }


def test_json_report_writes_populated_groups_and_quotes_spaced_arguments() -> None:
    takeover = {'old.example.test': {'status': 'vulnerable'}}
    report = _json(
        command_args=['-d', 'example test'],
        ips=['192.0.2.10'],
        emails=['admin@example.test'],
        hosts=['www.example.test:192.0.2.10'],
        virtual_hostnames=['admin.example.test'],
        urls=['https://www.example.test/'],
        asns=['AS64496'],
        prefixes={'198.51.100.0/24', '192.0.2.0/24'},
        people=[{'name': 'Example Person'}],
        takeover_results=takeover,
        shodan=[{'value': '192.0.2.10', 'details': {}}],
    )

    assert report == {
        'cmd': '-d "example test"',
        'ips': ['192.0.2.10'],
        'emails': ['admin@example.test'],
        'hosts': ['www.example.test:192.0.2.10'],
        'vhosts': ['admin.example.test'],
        'urls': ['https://www.example.test/'],
        'asns': ['AS64496'],
        'prefixes': ['192.0.2.0/24', '198.51.100.0/24'],
        'people': [{'name': 'Example Person'}],
        'takeover_results': takeover,
        'shodan': [{'value': '192.0.2.10', 'details': {}}],
    }


def test_xml_report_escapes_values_and_skips_hosts_already_paired() -> None:
    report = xml_report(
        command_args=['-d', 'a&b test'],
        emails=['<admin>@example.test'],
        host_ip_pairs={('www.example.test', '192.0.2.10')},
        hosts=['www.example.test:192.0.2.10', 'api.example.test:192.0.2.11', 'www.example.test', 'bare.example.test'],
        virtual_hostnames=['admin.example.test'],
    )

    assert report == (
        '<?xml version="1.0" encoding="UTF-8"?><theHarvester>'
        '<cmd>-d &quot;a&amp;b test&quot;</cmd>'
        '<email>&lt;admin&gt;@example.test</email>'
        '<host><ip>192.0.2.10</ip><hostname>www.example.test</hostname></host>'
        '<host><ip>192.0.2.11</ip><hostname>api.example.test</hostname></host>'
        '<host>bare.example.test</host>'
        '<vhost>admin.example.test</vhost>'
        '</theHarvester>'
    )


def test_xml_report_omits_hosts_when_hostname_collection_is_disabled() -> None:
    report = xml_report(
        command_args=[],
        emails=[],
        host_ip_pairs=None,
        hosts=['www.example.test'],
        virtual_hostnames=['admin.example.test'],
    )

    assert report == '<?xml version="1.0" encoding="UTF-8"?><theHarvester><cmd></cmd></theHarvester>'


def test_iter_xml_report_yields_earlier_elements_before_a_rendering_error() -> None:
    chunks = iter_xml_report(
        command_args=[],
        emails=['first@example.test', None],  # type: ignore[list-item]
        host_ip_pairs=None,
        hosts=[],
        virtual_hostnames=[],
    )
    written: list[str] = []

    with pytest.raises(AttributeError):
        for chunk in chunks:
            written.append(chunk)

    assert written == [
        '<?xml version="1.0" encoding="UTF-8"?><theHarvester>',
        '<cmd></cmd>',
        '<email>first@example.test</email>',
    ]
