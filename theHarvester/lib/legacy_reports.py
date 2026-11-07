"""Legacy grouped XML and JSON reports written beside the canonical JSONL output."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable, Mapping, Sequence


def sanitize_for_xml(text: str) -> str:
    """Sanitize text for safe inclusion in XML documents."""
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&apos;')
    return text


def _quoted_command(command_args: Iterable[str]) -> list[str]:
    return [f'"{arg}"' if ' ' in arg else arg for arg in command_args]


def _xml_host(host: str, ip: str) -> str:
    return f'<host><ip>{sanitize_for_xml(ip)}</ip><hostname>{sanitize_for_xml(host)}</hostname></host>'


def xml_report(
    *,
    command_args: Sequence[str],
    emails: Iterable[str],
    host_ip_pairs: Collection[tuple[str, str]] | None,
    hosts: Iterable[str],
    virtual_hostnames: Iterable[str],
) -> str:
    """Render the legacy XML report.

    ``host_ip_pairs`` is ``None`` when hostname collection is disabled, which
    omits every host and virtual-host element.
    """
    parts = ['<?xml version="1.0" encoding="UTF-8"?><theHarvester>']
    parts.append('<cmd>' + ' '.join(sanitize_for_xml(arg) for arg in _quoted_command(command_args)) + '</cmd>')
    parts.extend(f'<email>{sanitize_for_xml(email)}</email>' for email in emails)
    if host_ip_pairs is not None:
        paired_hosts = {host for host, _ip in host_ip_pairs}
        parts.extend(_xml_host(host, ip) for host, ip in sorted(host_ip_pairs))
        for entry in hosts:
            host, ip = entry.split(':', 1) if ':' in entry else (entry, '')
            if ip and len(ip) > 3:
                if (host, ip) not in host_ip_pairs:
                    parts.append(_xml_host(host, ip))
            elif host not in paired_hosts:
                parts.append(f'<host>{sanitize_for_xml(host)}</host>')
        parts.extend(f'<vhost>{sanitize_for_xml(host)}</vhost>' for host in virtual_hostnames)
    # TODO add Shodan output into XML report
    parts.append('</theHarvester>')
    return ''.join(parts)


def json_report(
    *,
    command_args: Sequence[str],
    ips: Sequence[str],
    emails: Sequence[str],
    hosts: Sequence[str] | None,
    virtual_hostnames: Sequence[str],
    urls: Sequence[str],
    asns: Sequence[str],
    prefixes: Iterable[str],
    people: Sequence[dict[str, str]],
    takeover_results: Mapping[str, object],
    shodan: Sequence[dict[str, object]],
) -> str:
    """Render the legacy grouped JSON report.

    Optional groups are written only when they have values. ``hosts`` is
    ``None`` when hostname collection is disabled, which omits the ``hosts``
    and ``vhosts`` keys; otherwise ``hosts`` is always present.
    """
    report: dict[str, object] = {'cmd': ' '.join(_quoted_command(command_args))}
    if ips:
        report['ips'] = ips
    if emails:
        report['emails'] = emails
    if hosts is not None:
        report['hosts'] = hosts
        if virtual_hostnames:
            report['vhosts'] = virtual_hostnames
    if urls:
        report['urls'] = urls
    if asns:
        report['asns'] = asns
    if sorted_prefixes := sorted(prefixes):
        report['prefixes'] = sorted_prefixes
    if people:
        report['people'] = people
    if takeover_results:
        report['takeover_results'] = takeover_results
    report['shodan'] = shodan
    return json.dumps(report, separators=(',', ':'), sort_keys=True)
