#!/usr/bin/env python3
# coding=utf-8
import pytest

from theHarvester.discovery import criminalip


@pytest.mark.asyncio
async def test_parser_handles_missing_legacy_fields(monkeypatch) -> None:
    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')

    search = criminalip.SearchCriminalIP('example.com')
    payload = {
        'data': {
            'certificates': [{'subject': 'www.example.com'}],
            'connected_domain_subdomain': [{'main_domain': {'domain': 'example.com'}, 'subdomains': [{'domain': 'api.example.com'}]}],
            'connected_ip': [{'ip': '93.184.216.34'}],
            'connected_ip_info': [
                {
                    'asn': '15133',
                    'ip': '93.184.216.34',
                    'domain_list': [{'domain': 'mail.example.com'}],
                }
            ],
            'cookies': [{'domain': '.portal.example.com'}],
            'dns_record': {
                'dns_record_type_a': {'ipv4': [{'ip': '93.184.216.34'}], 'ipv6': []},
                'dns_record_type_ns': ['ns1.example.com.'],
            },
            'html_page_link_domains': [{'domain': 'www.iana.org', 'mapped_ips': [{'ip': '192.0.33.8'}]}],
            'links': [{'url': 'https://docs.example.com/guide'}],
            'mapped_ip': [{'ip': '203.0.113.10'}],
            'network_logs': {
                'data': [{'url': 'https://cdn.example.com/script.js', 'as_number': '64500', 'ip_port': '198.51.100.10:443'}]
            },
            'page_redirections': [[{'url': 'https://login.example.com'}]],
            'subdomains': [{'subdomain_name': 'blog.example.com'}],
        }
    }

    await search.parser(payload)

    hostnames = await search.get_hostnames()
    ips = await search.get_ips()
    asns = await search.get_asns()

    assert {'api.example.com', 'blog.example.com', 'cdn.example.com', 'docs.example.com', 'login.example.com'}.issubset(hostnames)
    assert {'93.184.216.34', '198.51.100.10', '203.0.113.10'}.issubset(ips)
    assert {'15133', '64500'}.issubset(asns)


@pytest.mark.asyncio
async def test_do_search_uses_v2_report_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')
    monkeypatch.setattr(criminalip.Core, 'get_user_agent', lambda: 'test-agent')

    called_urls = []

    async def fake_post_fetch(url, **kwargs):
        assert url == 'https://api.criminalip.io/v1/domain/scan'
        return {'status': 200, 'data': {'scan_id': 12345}}

    async def fake_fetch_all(urls, **kwargs):
        called_urls.append(urls[0])
        if '/v1/domain/status/' in urls[0]:
            return [{'status': 200, 'data': {'scan_percentage': 100}}]
        if '/v2/domain/report/' in urls[0]:
            return [
                {
                    'status': 200,
                    'data': {
                        'certificates': [],
                        'connected_domain_subdomain': [],
                        'connected_ip': [],
                        'connected_ip_info': [],
                        'cookies': [],
                        'dns_record': {},
                        'html_page_link_domains': [],
                        'links': [],
                        'mapped_ip': [],
                        'network_logs': {'data': []},
                        'page_redirections': [],
                        'subdomains': [],
                    },
                }
            ]
        return [{'status': 500}]

    monkeypatch.setattr(criminalip.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(criminalip.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = criminalip.SearchCriminalIP('example.com')
    await search.process()

    assert any('/v2/domain/report/12345' in url for url in called_urls)
    assert all('/v1/domain/report/' not in url for url in called_urls)
