import asyncio

import pytest

from theHarvester.discovery import hackertarget as ht_mod
from theHarvester.lib.core import Core, FetcherResponse
from theHarvester.lib.source_catalog import ResultRoute, get_source_spec


class TestHackerTargetApiKey:
    def test_routes_include_subdomains_and_ips(self):
        assert get_source_spec('hackertarget').routes == {ResultRoute.SUBDOMAINS, ResultRoute.IPS}

    @pytest.mark.asyncio
    async def test_do_search_with_apikey(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: 'TESTKEY')
        requested_urls = []

        async def fake_fetch_all(urls, headers=None, proxy=False, include_metadata=False):
            requested_urls.extend(urls)
            assert proxy is True
            assert include_metadata is True
            return [
                FetcherResponse(
                    body='api.example.com,192.0.2.1\nmail.example.com,2001:db8::1\n',
                    status=200,
                    headers={},
                ),
                FetcherResponse(
                    body='ptr.example.com,192.0.2.2\n2001:db8::2 ipv6-ptr.example.com\n',
                    status=200,
                    headers={},
                ),
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)

        s = ht_mod.SearchHackerTarget('example.com')
        await s.process(proxy=True)

        assert requested_urls == [
            'https://api.hackertarget.com/hostsearch/?q=example.com&apikey=TESTKEY',
            'https://api.hackertarget.com/reversedns/?q=example.com&apikey=TESTKEY',
        ]
        assert await s.get_hostnames() == {
            'api.example.com',
            'mail.example.com',
            'ptr.example.com',
            'ipv6-ptr.example.com',
        }
        assert await s.get_ips() == {'192.0.2.1', '192.0.2.2', '2001:db8::1', '2001:db8::2'}

    @pytest.mark.asyncio
    async def test_do_search_without_apikey(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)
        requested_urls = []

        async def fake_fetch_all(urls, headers=None, proxy=False, include_metadata=False):
            requested_urls.extend(urls)
            assert include_metadata is True
            return [
                FetcherResponse(body='www.example.com,192.0.2.2\n', status=200, headers={}),
                FetcherResponse(body='No PTR records found', status=200, headers={}),
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)

        s = ht_mod.SearchHackerTarget('example.com')
        await s.process()

        assert requested_urls == [
            'https://api.hackertarget.com/hostsearch/?q=example.com',
            'https://api.hackertarget.com/reversedns/?q=example.com',
        ]
        assert await s.get_hostnames() == {'www.example.com'}
        assert await s.get_ips() == {'192.0.2.2'}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ('status', 'execution_status', 'stop_reason'),
        [(503, 'failed', 'http-503'), (429, 'rate-limited', 'http-429')],
    )
    async def test_http_failure_is_reported(self, monkeypatch, status, execution_status, stop_reason):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            return [
                FetcherResponse(body='service unavailable', status=status, headers={}),
                FetcherResponse(body='service unavailable', status=status, headers={}),
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        await search.process()

        assert search.execution_status == execution_status
        assert search.stop_reason == stop_reason
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()

    @pytest.mark.asyncio
    @pytest.mark.parametrize('body', ['', {}])
    async def test_empty_or_malformed_success_is_reported(self, monkeypatch, body: object):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            return [
                FetcherResponse(body=body, status=200, headers={}),
                FetcherResponse(body=body, status=200, headers={}),
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        await search.process()

        assert search.execution_status == 'failed'
        assert search.stop_reason == 'invalid-response'
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()

    @pytest.mark.asyncio
    async def test_out_of_scope_rows_do_not_contribute_ips(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            return [
                FetcherResponse(body='outside.example.net,192.0.2.44', status=200, headers={}),
                FetcherResponse(body='192.0.2.45 ptr.example.net', status=200, headers={}),
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        await search.process()

        assert search.execution_status == 'failed'
        assert search.stop_reason == 'invalid-response'
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()

    @pytest.mark.asyncio
    async def test_no_records_sentinel_is_a_valid_empty_result(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            return [
                FetcherResponse(body='No records found', status=200, headers={}),
                FetcherResponse(body='No PTR records found', status=200, headers={}),
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        await search.process()

        assert search.execution_status is None
        assert search.stop_reason is None
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ('failed_response', 'stop_reason'),
        [
            (FetcherResponse(body='service unavailable', status=503, headers={}), 'http-503'),
            (FetcherResponse(body='API count exceeded', status=200, headers={}), 'quota-exhausted'),
        ],
    )
    async def test_endpoint_failure_preserves_other_results(self, monkeypatch, failed_response, stop_reason):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            return [
                FetcherResponse(body='www.example.com,192.0.2.2\n', status=200, headers={}),
                failed_response,
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        await search.process()

        assert search.execution_status == 'partial'
        assert search.stop_reason == stop_reason
        assert await search.get_hostnames() == {'www.example.com'}
        assert await search.get_ips() == {'192.0.2.2'}

    @pytest.mark.asyncio
    async def test_valid_empty_endpoint_makes_other_failure_partial(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            return [
                FetcherResponse(body='No records found', status=200, headers={}),
                FetcherResponse(body='service unavailable', status=503, headers={}),
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        await search.process()

        assert search.execution_status == 'partial'
        assert search.stop_reason == 'http-503'
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()

    @pytest.mark.asyncio
    async def test_malformed_rows_preserve_valid_results_as_partial(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            return [
                FetcherResponse(body='www.example.com,192.0.2.2\nmalformed\n', status=200, headers={}),
                FetcherResponse(body='ptr.example.com,192.0.2.3\nmalformed\n', status=200, headers={}),
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        await search.process()

        assert search.execution_status == 'partial'
        assert search.stop_reason == 'invalid-response'
        assert await search.get_hostnames() == {'www.example.com', 'ptr.example.com'}
        assert await search.get_ips() == {'192.0.2.2', '192.0.2.3'}

    @pytest.mark.asyncio
    async def test_hyphenated_domain_still_uses_reverse_dns(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)
        target = '192.0.2.1-example.com'

        async def fake_fetch_all(urls, **_kwargs):
            assert urls == [
                f'https://api.hackertarget.com/hostsearch/?q={target}',
                f'https://api.hackertarget.com/reversedns/?q={target}',
            ]
            return [
                FetcherResponse(body='No records found', status=200, headers={}),
                FetcherResponse(body='No PTR records found', status=200, headers={}),
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget(target)

        await search.process()

        assert search.execution_status is None
        assert search.stop_reason is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        'target',
        [
            '192.0.2.1',
            ' 192.0.2.1 ',
            '192.0.2.0/24',
            '192.0.2.1-10',
            '192.0.2.1-192.0.2.10',
            '2001:db8::/32',
            '2001:db8::1-10',
            '2001:db8::1-2001:db8::10',
        ],
    )
    async def test_address_query_does_not_trigger_real_time_reverse_dns(self, monkeypatch, target):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(urls, **_kwargs):
            assert urls == [f'https://api.hackertarget.com/hostsearch/?q={target}']
            return [FetcherResponse(body='No records found', status=200, headers={})]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget(target)

        await search.process()

        assert search.execution_status is None
        assert search.stop_reason is None

    @pytest.mark.asyncio
    async def test_cancellation_propagates(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            raise asyncio.CancelledError

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        with pytest.raises(asyncio.CancelledError):
            await search.process(proxy=True)
