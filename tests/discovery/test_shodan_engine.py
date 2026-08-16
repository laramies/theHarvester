import asyncio
import logging
import socket
import sys
from collections import OrderedDict
from datetime import UTC
from types import SimpleNamespace
from uuid import UUID

import pytest


def patch_resolution(monkeypatch, module, addresses=('203.0.113.10',)):
    requested_targets = []

    async def resolve_ip_addresses(target, *, family=socket.AF_UNSPEC):
        requested_targets.append((target, family))
        return tuple(addresses)

    monkeypatch.setattr(module, 'resolve_ip_addresses', resolve_ip_addresses, raising=True)
    return requested_targets


@pytest.fixture(autouse=True)
def disable_shodan_pacing(monkeypatch):
    from theHarvester.discovery import shodansearch

    monkeypatch.setattr(shodansearch.SearchShodan, 'REQUEST_INTERVAL_SECONDS', 0.0)


class TestShodanEngine:
    @pytest.mark.asyncio
    async def test_shared_ipv4_resolution_returns_every_unique_address_and_closes(self, monkeypatch):
        from theHarvester.lib import hostchecker

        closed = False

        class Resolver:
            async def getaddrinfo(self, target, *, family):
                assert target == 'example.test'
                assert family == socket.AF_INET
                return SimpleNamespace(
                    nodes=[
                        SimpleNamespace(addr=(b'203.0.113.11', 0)),
                        SimpleNamespace(addr=('invalid', 0)),
                        SimpleNamespace(addr=('203.0.113.10', 0)),
                        SimpleNamespace(addr=('203.0.113.11', 0)),
                    ]
                )

            async def close(self):
                nonlocal closed
                closed = True

        monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', Resolver)

        assert await hostchecker.resolve_ip_addresses('example.test', family=socket.AF_INET) == (
            '203.0.113.10',
            '203.0.113.11',
        )
        assert closed is True

    @pytest.mark.asyncio
    async def test_shodan_calls_direct_host_api_through_proxy_and_retains_attribution(self, monkeypatch):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import FetcherResponse

        async def fetch_json(url, *, params, proxy, request_timeout):
            assert url == 'https://api.shodan.io/shodan/host/192.0.2.10'
            assert 'test-key' not in url
            assert params == {'key': 'test-key'}
            assert proxy is True
            assert request_timeout is None
            return FetcherResponse(
                body={
                    'asn': 'AS64496',
                    'domains': ['Example.TEST.'],
                    'hostnames': ['API.Example.TEST.'],
                    'ip_str': '192.0.2.10',
                    'isp': 'Example ISP Label',
                    'org': 'Example Transit',
                    'data': [
                        {
                            'port': 53,
                            'transport': 'udp',
                            'product': 'dnsmasq',
                            'version': '2.90',
                            'timestamp': '2026-08-14T11:58:00Z',
                            'cpe': ['cpe:/a:thekelleys:dnsmasq:2.90'],
                            'data': 'raw provider banner must not be retained',
                        },
                        {
                            'port': 443,
                            'transport': 'tcp',
                            'product': 'nginx',
                            'version': '1.24.0',
                            'timestamp': '2026-08-14T12:01:00Z',
                            'http': {
                                'components': {'nginx': {}, 'Python': {}},
                                'server': 'nginx',
                                'title': 'Example',
                                'html': 'raw response body must not be retained',
                            },
                            'ssl': {
                                'jarm': 'example-jarm',
                                'cert': {
                                    'subject': {'CN': 'api.example.test'},
                                    'issuer': {'CN': 'Example CA'},
                                    'expires': '2027-08-14T00:00:00Z',
                                    'fingerprint': {'sha256': '0123456789abcdef'},
                                    'extensions': [
                                        {
                                            'name': 'subjectAltName',
                                            'data': r'0\x82\x10api.example.test\x82\x10www.example.test',
                                        }
                                    ],
                                },
                            },
                        },
                    ],
                },
                status=200,
                headers={},
            )

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)
        search = shodansearch.SearchShodan()

        result = await search.search_ip('192.0.2.10', proxy=True)

        assert result['192.0.2.10'] == {
            'asn': 'AS64496',
            'domains': ['example.test'],
            'hostnames': ['api.example.test'],
            'isp': 'Example ISP Label',
            'organization': 'Example Transit',
            'services': [
                {
                    'cpes': ['cpe:/a:thekelleys:dnsmasq:2.90'],
                    'observed_at': '2026-08-14T11:58:00Z',
                    'port': 53,
                    'product': 'dnsmasq',
                    'transport': 'udp',
                    'version': '2.90',
                },
                {
                    'http': {
                        'components': ['Python', 'nginx'],
                        'server': 'nginx',
                        'title': 'Example',
                    },
                    'observed_at': '2026-08-14T12:01:00Z',
                    'port': 443,
                    'product': 'nginx',
                    'tls': {
                        'expires_at': '2027-08-14T00:00:00Z',
                        'issuer_cn': 'Example CA',
                        'jarm': 'example-jarm',
                        'sha256': '0123456789abcdef',
                        'subject_alt_names': ['www.example.test'],
                        'subject_cn': 'api.example.test',
                    },
                    'transport': 'tcp',
                    'version': '1.24.0',
                },
            ],
        }
        attribution = next(iter(await search.get_asn_attributions()))
        assert attribution.producer_kind == 'action'
        assert attribution.producer == 'shodan'
        assert attribution.asn == 'AS64496'
        assert attribution.organization_label == 'Example Transit'
        assert attribution.subject_kind == 'ip'
        assert attribution.subject_value == '192.0.2.10'
        assert attribution.collected_at.tzinfo is UTC

    @pytest.mark.asyncio
    async def test_shodan_maps_404_to_a_successful_zero_yield(self, monkeypatch, caplog):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import FetcherResponse

        async def fetch_json(*_args, **_kwargs):
            return FetcherResponse(body=None, status=404, headers={})

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)
        caplog.set_level(logging.INFO, logger=shodansearch.__name__)

        search = shodansearch.SearchShodan()
        result = await search.search_ip('203.0.113.1')

        assert result == OrderedDict({'203.0.113.1': 'Not in Shodan'})
        assert search.error_type is None
        assert '203.0.113.1: Not in Shodan' in caplog.text

    @pytest.mark.asyncio
    @pytest.mark.parametrize('status', [401, 403, 429, 500])
    async def test_shodan_classifies_http_failures_without_provider_payload(self, monkeypatch, caplog, status):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import FetcherResponse

        async def fetch_json(*_args, **_kwargs):
            return FetcherResponse(body=None, status=status, headers={'x-provider-secret': 'secret'})

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)
        caplog.set_level(logging.INFO, logger=shodansearch.__name__)

        search = shodansearch.SearchShodan()
        result = await search.search_ip('203.0.113.1')

        assert result == OrderedDict({'203.0.113.1': 'Shodan request failed'})
        assert search.error_type == f'HTTP{status}Error'
        assert 'secret' not in caplog.text

    @pytest.mark.asyncio
    async def test_shodan_classifies_bounded_transport_failure(self, monkeypatch):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import ResponseStreamError

        async def fetch_json(*_args, **_kwargs):
            raise ResponseStreamError('response-limit')

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)

        search = shodansearch.SearchShodan()
        result = await search.search_ip('203.0.113.1')

        assert result == OrderedDict({'203.0.113.1': 'Shodan request failed'})
        assert search.error_type == 'ResponseLimitError'

    @pytest.mark.asyncio
    async def test_shodan_discovery_queries_every_resolved_ipv4_and_keeps_partial_results(self, monkeypatch):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import FetcherResponse

        queried_urls = []

        async def fetch_json(url, **_kwargs):
            if url.endswith('/search'):
                return FetcherResponse(body={'matches': [], 'total': 0}, status=200, headers={})
            queried_urls.append(url)
            ip = url.rsplit('/', 1)[-1]
            if ip == '203.0.113.10':
                return FetcherResponse(body=None, status=500, headers={})
            return FetcherResponse(
                body={
                    'data': [{'ip_str': ip, 'port': 443, 'transport': 'tcp'}],
                    'hostnames': ['CDN.Example.TEST.', 'outside.test'],
                },
                status=200,
                headers={},
            )

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)
        targets = patch_resolution(monkeypatch, shodansearch, ('203.0.113.10', '203.0.113.11'))

        search = shodansearch.SearchShodan('WWW.Example.TEST.')
        await search.process(proxy=True)

        assert targets == [('www.example.test', socket.AF_INET)]
        assert queried_urls == [
            'https://api.shodan.io/shodan/host/203.0.113.10',
            'https://api.shodan.io/shodan/host/203.0.113.11',
        ]
        assert await search.get_hostnames() == {'cdn.example.test'}
        assert search.execution_status == 'partial'
        assert search.stop_reason == 'provider-errors'

    @pytest.mark.asyncio
    async def test_shodan_discovery_paginates_hostname_and_tls_searches_with_scoped_certificate_names(self, monkeypatch):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import FetcherResponse

        search_calls = []

        def banner(
            ip,
            port,
            *,
            hostnames=(),
            subject_cn=None,
            subject_alt_name='',
        ):
            cert = {
                'extensions': [
                    {'name': 'subjectAltName', 'data': subject_alt_name},
                    {'name': 'keyUsage', 'data': 'Digital Signature'},
                ]
            }
            if subject_cn is not None:
                cert['subject'] = {'CN': subject_cn}
            return {
                'ip_str': ip,
                'hostnames': list(hostnames),
                'port': port,
                'transport': 'tcp',
                'ssl': {'cert': cert},
            }

        hostname_pages = {
            1: {
                'total': 2,
                'matches': [
                    banner(
                        '198.51.100.20',
                        443,
                        hostnames=('API.Example.TEST.',),
                        subject_cn='*.example.test',
                        subject_alt_name=(r'0\x82\x10api.example.test\x82\x12outside.invalid\x82\x13vpn.example.test'),
                    )
                ],
            },
            2: {
                'total': 2,
                'matches': [banner('198.51.100.20', 8443, hostnames=('api.example.test',))],
            },
        }
        ssl_page = {
            'total': 3,
            'matches': [
                banner(
                    '198.51.100.20',
                    443,
                    hostnames=('api.example.test',),
                    subject_cn='*.example.test',
                    subject_alt_name=r'0\x82\x10api.example.test\x82\x13vpn.example.test',
                ),
                banner(
                    '198.51.100.21',
                    443,
                    subject_cn='cert.example.test',
                    subject_alt_name=r'0\x82\x13cert.example.test\x82\x15outside.invalid',
                ),
                banner(
                    '198.51.100.22',
                    443,
                    hostnames=('outside.invalid',),
                    subject_cn='outside.invalid',
                    subject_alt_name=r'0\x82\x15outside.invalid',
                ),
            ],
        }

        async def fetch_json(url, *, params, proxy, request_timeout):
            assert proxy is True
            assert request_timeout is None
            assert params['key'] == 'test-key'
            if url.endswith('/search'):
                search_calls.append(dict(params))
                query = params['query']
                if query == 'hostname:example.test':
                    return FetcherResponse(body=hostname_pages[params['page']], status=200, headers={})
                assert query == 'ssl:example.test'
                assert params['page'] == 1
                return FetcherResponse(body=ssl_page, status=200, headers={})
            assert url == 'https://api.shodan.io/shodan/host/203.0.113.10'
            return FetcherResponse(
                body={'data': [{'port': 80, 'transport': 'tcp'}], 'hostnames': ['www.example.test']},
                status=200,
                headers={},
            )

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)
        patch_resolution(monkeypatch, shodansearch)

        search = shodansearch.SearchShodan('example.test')
        await search.process(proxy=True)

        assert [(call['query'], call['page']) for call in search_calls] == [
            ('hostname:example.test', 1),
            ('hostname:example.test', 2),
            ('ssl:example.test', 1),
        ]
        assert all(call['minify'] == 'false' and call['fields'] == search.SEARCH_FIELDS for call in search_calls)
        assert await search.get_hostnames() == {
            'api.example.test',
            'cert.example.test',
            'vpn.example.test',
            'www.example.test',
        }
        hosts = {host.ip: host.to_details() for host in await search.get_shodan_hosts()}
        assert set(hosts) == {'198.51.100.20', '198.51.100.21', '203.0.113.10'}
        assert [service['port'] for service in hosts['198.51.100.20']['services']] == [443, 8443]
        assert hosts['198.51.100.20']['services'][0]['tls'] == {
            'subject_alt_names': ['api.example.test', 'vpn.example.test'],
            'subject_cn': '*.example.test',
        }
        assert hosts['198.51.100.21']['services'][0]['tls'] == {'subject_cn': 'cert.example.test'}
        assert search.execution_status == 'completed'
        assert search.stop_reason is None

    @pytest.mark.asyncio
    async def test_shodan_discovery_counts_service_only_evidence_as_a_result(self, monkeypatch):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import FetcherResponse

        async def fetch_json(url, **_kwargs):
            if url.endswith('/search'):
                return FetcherResponse(body={'matches': [], 'total': 0}, status=200, headers={})
            return FetcherResponse(
                body={'data': [{'port': 53, 'transport': 'udp'}], 'hostnames': []},
                status=200,
                headers={},
            )

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)
        patch_resolution(monkeypatch, shodansearch)

        search = shodansearch.SearchShodan('example.test')
        await search.process()

        assert search.execution_status == 'completed'
        assert search.stop_reason is None
        assert [host.ip for host in await search.get_shodan_hosts()] == ['203.0.113.10']

    @pytest.mark.asyncio
    async def test_shodan_discovery_retains_valid_services_and_reports_malformed_provider_data(self, monkeypatch):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import FetcherResponse

        async def fetch_json(*_args, **_kwargs):
            return FetcherResponse(
                body={
                    'data': [
                        {'port': 53, 'transport': 'udp', 'product': {'raw': 'provider object'}},
                        {'transport': 'tcp'},
                    ],
                    'hostnames': [],
                },
                status=200,
                headers={},
            )

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)
        patch_resolution(monkeypatch, shodansearch)

        search = shodansearch.SearchShodan('example.test')
        await search.process()

        assert search.execution_status == 'partial'
        assert search.stop_reason == 'provider-error'
        assert search.error_type == 'InvalidResponseError'
        assert (await search.get_shodan_hosts())[0].to_details() == {'services': [{'port': 53, 'transport': 'udp'}]}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ('status', 'expected_reason'),
        [(401, 'access-denied'), (403, 'access-denied'), (429, 'rate-limited')],
    )
    async def test_shodan_discovery_reports_specific_provider_stop_reason(self, monkeypatch, status, expected_reason):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import FetcherResponse

        async def fetch_json(*_args, **_kwargs):
            return FetcherResponse(body=None, status=status, headers={})

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)
        patch_resolution(monkeypatch, shodansearch)

        search = shodansearch.SearchShodan('example.test')
        await search.process()

        assert search.execution_status == 'failed'
        assert search.stop_reason == expected_reason

    def test_shodan_discovery_requires_a_configured_key(self, monkeypatch):
        from theHarvester.discovery import shodansearch
        from theHarvester.discovery.constants import MissingKey

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: None)

        with pytest.raises(MissingKey):
            shodansearch.SearchShodan('example.test')

    def test_shodan_discovery_rejects_query_filter_injection(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')

        with pytest.raises(ValueError, match='must be a hostname'):
            shodansearch.SearchShodan('example.test ssl:true')

    @pytest.mark.asyncio
    async def test_shodan_discovery_reports_dns_failure_after_searching_provider(self, monkeypatch):
        from theHarvester.discovery import shodansearch
        from theHarvester.lib.core import FetcherResponse

        provider_queries = []

        async def fail_resolution(_target, *, family):
            assert family == socket.AF_INET
            raise shodansearch.aiodns.error.DNSError(shodansearch.aiodns.error.ARES_ENOTFOUND, 'not found')

        async def fetch_json(url, *, params, **_kwargs):
            assert url.endswith('/search')
            provider_queries.append(params['query'])
            return FetcherResponse(body={'matches': [], 'total': 0}, status=200, headers={})

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'resolve_ip_addresses', fail_resolution)
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)

        search = shodansearch.SearchShodan('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert provider_queries == ['hostname:example.test', 'ssl:example.test']
        assert search.execution_status == 'failed'
        assert search.stop_reason == 'dns-resolution-failed'

    @pytest.mark.asyncio
    async def test_shodan_direct_request_cancellation_propagates(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        entered = asyncio.Event()
        release = asyncio.Event()

        async def fetch_json(*_args, **_kwargs):
            entered.set()
            await release.wait()
            raise AssertionError('cancelled request resumed')

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch.AsyncFetcher, 'fetch_json', fetch_json)
        patch_resolution(monkeypatch, shodansearch)

        task = asyncio.create_task(shodansearch.SearchShodan('example.test').process())
        await entered.wait()
        task.cancel('operator-stop')
        with pytest.raises(asyncio.CancelledError, match='operator-stop'):
            await task
        release.set()

    @pytest.mark.asyncio
    async def test_shodan_engine_processes_and_persists_sourced_hostnames(self, monkeypatch, capsys, tmp_path):
        import theHarvester.__main__ as main_module
        from theHarvester.lib.completed_result import ResultObservation, SourceExecution
        from theHarvester.lib.database import ResultStore
        from theHarvester.lib.shodan_evidence import ShodanHostObservation

        database = tmp_path / 'stash.sqlite'
        monkeypatch.setattr(main_module, 'ResultStore', lambda: ResultStore(database), raising=True)

        class DummySearchShodan:
            def __init__(self, domain):
                assert domain == 'example.com'
                self.shodan_host = ShodanHostObservation.from_record(
                    '192.0.2.10',
                    {
                        'organization': 'Example Transit',
                        'hostnames': ['a.example.com', 'b.example.com'],
                        'services': [
                            {'port': 53, 'transport': 'udp'},
                            {'port': 443, 'transport': 'tcp', 'product': 'nginx'},
                        ],
                    },
                )

            async def process(self, proxy=False):
                return None

            async def get_hostnames(self):
                return {'a.example.com', 'b.example.com'}

            async def get_shodan_hosts(self):
                return (self.shodan_host,)

        monkeypatch.setattr(main_module.shodansearch, 'SearchShodan', DummySearchShodan, raising=True)
        monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'shodan'], raising=True)

        with pytest.raises(SystemExit) as excinfo:
            await main_module.start()
        assert excinfo.value.code == 0

        out = capsys.readouterr().out
        assert 'An error occurred while processing a "work item"' not in out
        assert {'a.example.com', 'b.example.com'} <= set(out.split())
        assert '"type": "shodan-host"' in out
        assert '"value": "192.0.2.10"' in out
        assert '"transport": "udp"' in out
        assert '"transport": "tcp"' in out

        store = ResultStore(database)
        try:
            runs = await store.list_runs()
            completed = await store.load_run(UUID(str(runs[0]['run_id'])))
            assert len(completed.source_executions) == 1
            execution = completed.source_executions[0]
            assert execution == SourceExecution('shodan', 'completed', execution.duration_ms, 3)
            assert completed.observations == (
                ResultObservation('shodan', 'hostname', 'a.example.com'),
                ResultObservation('shodan', 'hostname', 'b.example.com'),
                ResultObservation('shodan', 'shodan-host', '192.0.2.10'),
            )
            assert completed.shodan_hosts == (DummySearchShodan('example.com').shodan_host,)
        finally:
            await store.dispose()

    @pytest.mark.asyncio
    async def test_shodan_internetdb_uses_shared_resolution_and_normalizes_scope(self, monkeypatch):
        from theHarvester.discovery import shodan_internetdb

        targets = patch_resolution(monkeypatch, shodan_internetdb, ('203.0.113.1',))

        async def fake_fetch_all(urls, json=False, proxy=False):
            assert urls == ['https://internetdb.shodan.io/203.0.113.1']
            return [
                {
                    'ip': '203.0.113.1',
                    'hostnames': ['API.Example.TEST.', 'www.notexample.test', None],
                    'ports': [443],
                }
            ]

        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fake_fetch_all, raising=True)

        search = shodan_internetdb.SearchShodanInternetDB(' Example.TEST. ')
        await search.process()

        assert targets == [('example.test', socket.AF_UNSPEC)]
        assert await search.get_hostnames() == {'api.example.test'}
        assert await search.get_ips() == {'203.0.113.1'}

    @pytest.mark.asyncio
    async def test_shodan_internetdb_rejects_evidence_for_an_unrequested_ip(self, monkeypatch):
        from theHarvester.discovery import shodan_internetdb

        patch_resolution(monkeypatch, shodan_internetdb, ('203.0.113.1',))

        async def fake_fetch_all(_urls, json=False, proxy=False):
            return [
                {
                    'ip': '198.51.100.2',
                    'hostnames': ['injected.example.test'],
                    'ports': [443],
                    'vulns': ['CVE-2026-0001'],
                    'tags': ['injected'],
                    'cpes': ['cpe:/a:injected'],
                }
            ]

        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fake_fetch_all, raising=True)

        search = shodan_internetdb.SearchShodanInternetDB('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert not await search.get_ips()
        assert not await search.get_ports()
        assert not await search.get_vulns()
        assert not await search.get_tags()
        assert not await search.get_cpes()

    @pytest.mark.asyncio
    async def test_shodan_internetdb_resolution_failure_skips_provider_request(self, monkeypatch):
        from theHarvester.discovery import shodan_internetdb

        async def fail_resolution(_target):
            raise shodan_internetdb.aiodns.error.DNSError(shodan_internetdb.aiodns.error.ARES_ENOTFOUND, 'not found')

        async def fail_fetch(*_args, **_kwargs):
            raise AssertionError('provider request must not run')

        monkeypatch.setattr(shodan_internetdb, 'resolve_ip_addresses', fail_resolution)
        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fail_fetch, raising=True)

        search = shodan_internetdb.SearchShodanInternetDB('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert not await search.get_ips()

    @pytest.mark.asyncio
    async def test_shodan_internetdb_provider_failure_completes_without_evidence(self, monkeypatch, caplog):
        from theHarvester.discovery import shodan_internetdb

        patch_resolution(monkeypatch, shodan_internetdb, ('203.0.113.1',))

        async def fail_fetch(*_args, **_kwargs):
            raise RuntimeError('provider-secret-payload')

        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fail_fetch, raising=True)
        caplog.set_level(logging.INFO, logger=shodan_internetdb.__name__)

        search = shodan_internetdb.SearchShodanInternetDB('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert not await search.get_ips()
        assert 'Shodan InternetDB request failed' in caplog.text
        assert 'provider-secret-payload' not in caplog.text


pytestmark = [
    pytest.mark.provider_contract('shodan'),
    pytest.mark.provider_contract('shodanInternetDB'),
]
