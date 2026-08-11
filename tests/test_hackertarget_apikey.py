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
                )
            ]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)

        s = ht_mod.SearchHackerTarget('example.com')
        await s.process(proxy=True)

        assert requested_urls == ['https://api.hackertarget.com/hostsearch/?q=example.com&apikey=TESTKEY']
        assert await s.get_hostnames() == {'api.example.com', 'mail.example.com'}
        assert await s.get_ips() == {'192.0.2.1', '2001:db8::1'}

    @pytest.mark.asyncio
    async def test_do_search_without_apikey(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)
        requested_urls = []

        async def fake_fetch_all(urls, headers=None, proxy=False, include_metadata=False):
            requested_urls.extend(urls)
            assert include_metadata is True
            return [FetcherResponse(body='www.example.com,192.0.2.2\n', status=200, headers={})]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)

        s = ht_mod.SearchHackerTarget('example.com')
        await s.process()

        assert requested_urls == ['https://api.hackertarget.com/hostsearch/?q=example.com']
        assert await s.get_hostnames() == {'www.example.com'}
        assert await s.get_ips() == {'192.0.2.2'}

    @pytest.mark.asyncio
    async def test_http_failure_is_reported(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            return [FetcherResponse(body='service unavailable', status=503, headers={})]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        await search.process()

        assert search.execution_status == 'failed'
        assert search.stop_reason == 'http-503'
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()

    @pytest.mark.asyncio
    @pytest.mark.parametrize('body', ['', {}])
    async def test_empty_or_malformed_success_is_reported(self, monkeypatch, body: object):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            return [FetcherResponse(body=body, status=200, headers={})]

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
            return [FetcherResponse(body='outside.example.net,192.0.2.44', status=200, headers={})]

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
            return [FetcherResponse(body='No records found', status=200, headers={})]

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        await search.process()

        assert search.execution_status is None
        assert search.stop_reason is None
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()

    @pytest.mark.asyncio
    async def test_cancellation_propagates(self, monkeypatch):
        monkeypatch.setattr(Core, 'hackertarget_key', lambda: None)

        async def fake_fetch_all(*_args, **_kwargs):
            raise asyncio.CancelledError

        monkeypatch.setattr(ht_mod.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = ht_mod.SearchHackerTarget('example.com')

        with pytest.raises(asyncio.CancelledError):
            await search.process(proxy=True)
