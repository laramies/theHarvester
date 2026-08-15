import asyncio

import pytest

from theHarvester.discovery import crtsh
from theHarvester.lib.core import FetcherResponse


def _patch_fetch(monkeypatch, payload):
    import theHarvester.lib.core as core_module

    calls = []

    async def fake_fetch_all(urls, headers=None, proxy=False, json=False, include_metadata=False):
        calls.append(urls)
        assert include_metadata is True
        return [FetcherResponse(body=payload, status=200, headers={})]

    monkeypatch.setattr(core_module.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all), raising=True)
    return calls


def _patch_sleep(monkeypatch):
    delays = []

    async def fake_sleep(delay):
        delays.append(delay)

    monkeypatch.setattr(asyncio, 'sleep', fake_sleep)
    return delays


class TestCrtshSearch:
    def test_init_sets_state(self):
        search = crtsh.SearchCrtsh('example.com')
        assert search.word == 'example.com'
        assert search.data == []
        assert search.proxy is False

    @pytest.mark.asyncio
    async def test_process_collects_hostnames(self, monkeypatch):
        _patch_fetch(monkeypatch, [{'name_value': 'www.example.com'}, {'name_value': 'mail.example.com'}])
        search = crtsh.SearchCrtsh('example.com')
        await search.process(proxy=True)
        assert search.proxy is True
        assert set(await search.get_hostnames()) == {'www.example.com', 'mail.example.com'}

    @pytest.mark.asyncio
    async def test_wildcard_prefix_is_stripped(self, monkeypatch):
        _patch_fetch(monkeypatch, [{'name_value': '*.example.com'}])
        search = crtsh.SearchCrtsh('example.com')
        await search.process()
        assert set(await search.get_hostnames()) == {'example.com'}

    @pytest.mark.asyncio
    async def test_multiline_name_value_is_split(self, monkeypatch):
        # crt.sh packs several names into one name_value separated by newlines.
        _patch_fetch(monkeypatch, [{'name_value': 'a.example.com\nb.example.com'}])
        search = crtsh.SearchCrtsh('example.com')
        await search.process()
        assert set(await search.get_hostnames()) == {'a.example.com', 'b.example.com'}

    @pytest.mark.asyncio
    async def test_numeric_prefixed_entries_are_preserved(self, monkeypatch):
        _patch_fetch(monkeypatch, [{'name_value': '1234.example.com'}, {'name_value': 'good.example.com'}])
        search = crtsh.SearchCrtsh('example.com')
        await search.process()
        assert set(await search.get_hostnames()) == {'1234.example.com', 'good.example.com'}

    @pytest.mark.asyncio
    async def test_empty_response_returns_no_hostnames(self, monkeypatch):
        fetches = _patch_fetch(monkeypatch, [])
        delays = _patch_sleep(monkeypatch)
        search = crtsh.SearchCrtsh('example.com')
        await search.process()

        assert len(fetches) == 1
        assert delays == []
        assert await search.get_hostnames() == []
        assert search.execution_status is None
        assert search.stop_reason is None

    @pytest.mark.asyncio
    async def test_failed_fetches_are_retried_with_delay(self, monkeypatch):
        import theHarvester.lib.core as core_module

        payloads = iter([None, None, FetcherResponse([{'name_value': 'api.example.com'}], 200, {})])
        fetch_count = 0

        async def fake_fetch_all(urls, headers=None, proxy=False, json=False, include_metadata=False):
            nonlocal fetch_count
            fetch_count += 1
            assert include_metadata is True
            return [next(payloads)]

        monkeypatch.setattr(core_module.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all), raising=True)
        delays = _patch_sleep(monkeypatch)

        search = crtsh.SearchCrtsh('example.com')
        await search.process()

        assert fetch_count == 3
        assert delays == [2, 2]
        assert await search.get_hostnames() == ['api.example.com']

    @pytest.mark.asyncio
    async def test_exhausted_http_failures_are_reported(self, monkeypatch):
        fetch_count = 0

        async def fake_fetch_all(urls, headers=None, proxy=False, json=False, include_metadata=False):
            nonlocal fetch_count
            fetch_count += 1
            assert json is True
            assert include_metadata is True
            return [FetcherResponse(body='bad gateway', status=502, headers={})]

        monkeypatch.setattr(crtsh.AsyncFetcher, 'fetch_all', fake_fetch_all)
        delays = _patch_sleep(monkeypatch)
        search = crtsh.SearchCrtsh('example.com')

        await search.process()

        assert fetch_count == 3
        assert delays == [2, 2]
        assert await search.get_hostnames() == []
        assert search.execution_status == 'failed'
        assert search.stop_reason == 'http-502'

    @pytest.mark.asyncio
    async def test_cancellation_propagates(self, monkeypatch):
        async def fake_fetch_all(*_args, **_kwargs):
            raise asyncio.CancelledError

        monkeypatch.setattr(crtsh.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = crtsh.SearchCrtsh('example.com')

        with pytest.raises(asyncio.CancelledError):
            await search.process(proxy=True)

    @pytest.mark.asyncio
    async def test_stalled_provider_is_bounded_and_reported(self, monkeypatch):
        async def fake_fetch_all(*_args, **_kwargs):
            await asyncio.Event().wait()

        monkeypatch.setattr(crtsh.AsyncFetcher, 'fetch_all', fake_fetch_all)
        monkeypatch.setattr(crtsh.SearchCrtsh, 'RUNTIME_SECONDS', 0.01)
        search = crtsh.SearchCrtsh('example.com')

        await asyncio.wait_for(search.process(), timeout=1.0)

        assert await search.get_hostnames() == []
        assert search.execution_status == 'failed'
        assert search.stop_reason == 'runtime-limit'

    @pytest.mark.asyncio
    async def test_missing_name_value_key_is_handled(self, monkeypatch):
        fetches = _patch_fetch(monkeypatch, [{'issuer_ca_id': 1}])
        delays = _patch_sleep(monkeypatch)
        search = crtsh.SearchCrtsh('example.com')
        await search.process()

        assert len(fetches) == 1
        assert delays == []
        assert await search.get_hostnames() == []


class TestCrtshIntegration:
    def test_source_catalog_lists_crtsh(self):
        from theHarvester.lib.source_catalog import SOURCE_SPECS

        assert 'crtsh' in SOURCE_SPECS
