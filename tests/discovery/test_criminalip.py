#!/usr/bin/env python3
import asyncio
import logging

import pytest

from theHarvester.discovery import criminalip
from theHarvester.lib import core as core_module
from theHarvester.lib.source_execution import SourceExecutionReport


@pytest.mark.asyncio
async def test_failed_response_body_is_not_logged(monkeypatch, caplog) -> None:
    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')
    monkeypatch.setattr(criminalip.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_post_fetch(*args, **kwargs):
        return {'status': 500, 'secret': 'provider-secret-payload'}

    monkeypatch.setattr(criminalip.AsyncFetcher, 'post_fetch', fake_post_fetch)
    caplog.set_level(logging.INFO, logger=criminalip.__name__)

    report = await criminalip.SearchCriminalIP('example.com').process()

    assert report == SourceExecutionReport('failed', 'provider-error')
    assert 'provider-secret-payload' not in caplog.text
    assert '500' in caplog.text


@pytest.mark.asyncio
async def test_parser_handles_missing_legacy_fields(monkeypatch) -> None:
    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')

    search = criminalip.SearchCriminalIP('example.com')
    payload = {
        'data': {
            'certificates': [{'subject': 'www.example.com'}],
            'connected_domain_subdomain': [
                {'main_domain': {'domain': 'example.com'}, 'subdomains': [{'domain': 'api.example.com'}]}
            ],
            'connected_ip': [{'ip': '192.0.2.34'}],
            'connected_ip_info': [
                {
                    'asn': '15133',
                    'ip': '192.0.2.34',
                    'domain_list': [{'domain': 'mail.example.com'}],
                }
            ],
            'cookies': [{'domain': '.portal.example.com'}],
            'dns_record': {
                'dns_record_type_a': {'ipv4': [{'ip': '192.0.2.34'}], 'ipv6': []},
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

    assert {
        'api.example.com',
        'blog.example.com',
        'cdn.example.com',
        'docs.example.com',
        'login.example.com',
        'www.example.com',
    }.issubset(hostnames)
    assert {'192.0.2.34', '198.51.100.10', '203.0.113.10'}.issubset(ips)
    assert {'15133', '64500'}.issubset(asns)


@pytest.mark.asyncio
async def test_do_search_uses_v2_report_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')
    monkeypatch.setattr(criminalip.Core, 'get_user_agent', lambda: 'test-agent')

    called_urls = []

    async def fake_post_fetch(url, **kwargs):
        assert url == 'https://api.criminalip.io/v1/domain/scan'
        return {'status': 200, 'data': {'scan_id': 12345}}

    async def fake_fetch(*_args, url, **_kwargs):
        called_urls.append(url)
        if '/v1/domain/status/' in url:
            return {'status': 200, 'data': {'scan_percentage': 100}}
        if '/v2/domain/report/' in url:
            return {'status': 200, 'data': {}}
        return {'status': 500}

    monkeypatch.setattr(criminalip.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(criminalip.AsyncFetcher, 'fetch', fake_fetch)

    search = criminalip.SearchCriminalIP('example.com')
    await search.process()

    assert any('/v2/domain/report/12345' in url for url in called_urls)
    assert all('/v1/domain/report/' not in url for url in called_urls)


@pytest.mark.asyncio
async def test_provider_conversation_uses_one_session_and_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {
        'https://api.criminalip.io/v1/domain/scan': {'status': 200, 'data': {'scan_id': 12345}},
        'https://api.criminalip.io/v1/domain/status/12345': {'status': 200, 'data': {'scan_percentage': 100}},
        'https://api.criminalip.io/v2/domain/report/12345': {'status': 200, 'data': {}},
    }
    sessions = []
    selections = []

    class Response:
        status = 200

        def __init__(self, body) -> None:
            self.body = body
            self.headers = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def json(self):
            return self.body

    class Session:
        def __init__(self) -> None:
            self.closed = False
            self.urls = []

        def request(self, _method: str, url: str, **_kwargs):
            self.urls.append(url)
            return Response(responses[url])

        async def close(self) -> None:
            self.closed = True

    def choose(proxies):
        selections.append(tuple(proxies))
        return proxies[len(selections) % 2]

    async def build_session(*_args, **_kwargs):
        session = Session()
        sessions.append(session)
        return session

    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')
    monkeypatch.setattr(criminalip.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(criminalip.AsyncFetcher, '_proxy_list', {'http': ['http://one.example', 'http://two.example']})
    monkeypatch.setattr(core_module.random, 'choice', choose)
    monkeypatch.setattr(criminalip.AsyncFetcher, '_ssl_context', staticmethod(lambda _verify=True: object()))
    monkeypatch.setattr(criminalip.AsyncFetcher, '_build_session', build_session)

    assert await criminalip.SearchCriminalIP('example.com').process(proxy=True) is None
    assert len(selections) == 1
    assert len(sessions) == 1
    assert sessions[0].urls == list(responses)
    assert sessions[0].closed is True


@pytest.mark.asyncio
async def test_required_proxy_unavailable_returns_explicit_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')
    monkeypatch.setattr(criminalip.AsyncFetcher, '_proxy_list', {})

    assert await criminalip.SearchCriminalIP('example.com').process(proxy=True) == SourceExecutionReport(
        'failed', 'proxy-unavailable'
    )


@pytest.mark.asyncio
async def test_waiting_scan_reports_runtime_limit(monkeypatch) -> None:
    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')
    monkeypatch.setattr(criminalip.Core, 'get_user_agent', lambda: 'test-agent')
    status_calls = 0

    async def fake_post_fetch(*_args, **_kwargs):
        return {'status': 200, 'data': {'scan_id': 12345}}

    async def fake_fetch(*_args, **_kwargs):
        nonlocal status_calls
        status_calls += 1
        return {'status': 200, 'data': {'scan_percentage': 50}}

    async def no_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(criminalip.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(criminalip.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(criminalip.asyncio, 'sleep', no_sleep)

    report = await criminalip.SearchCriminalIP('example.com').process()

    assert status_calls == 10
    assert report == SourceExecutionReport('partial', 'runtime-limit')


@pytest.mark.asyncio
async def test_polling_cancellation_propagates(monkeypatch) -> None:
    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')
    monkeypatch.setattr(criminalip.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_post_fetch(*_args, **_kwargs):
        return {'status': 200, 'data': {'scan_id': 12345}}

    async def fake_fetch(*_args, **_kwargs):
        return {'status': 200, 'data': {'scan_percentage': 50}}

    async def cancel(*_args, **_kwargs):
        raise asyncio.CancelledError

    monkeypatch.setattr(criminalip.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(criminalip.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(criminalip.asyncio, 'sleep', cancel)

    with pytest.raises(asyncio.CancelledError):
        await criminalip.SearchCriminalIP('example.com').process()


@pytest.mark.asyncio
async def test_provider_timeout_returns_explicit_transport_error(monkeypatch) -> None:
    monkeypatch.setattr(criminalip.Core, 'criminalip_key', lambda: 'test-key')
    monkeypatch.setattr(criminalip.Core, 'get_user_agent', lambda: 'test-agent')

    async def timeout(*_args, **_kwargs):
        raise TimeoutError

    monkeypatch.setattr(criminalip.AsyncFetcher, 'post_fetch', timeout)

    assert await criminalip.SearchCriminalIP('example.com').process() == SourceExecutionReport('failed', 'transport-error')


pytestmark = pytest.mark.provider_contract('criminalip')
