import pytest

from theHarvester.discovery import bufferoverun


def _patch_fetch(monkeypatch, payload):
    import theHarvester.lib.core as core_module

    async def fake_fetch_all(urls, headers=None, params='', json=False, takeover=False, proxy=False):
        return [payload]

    monkeypatch.setattr(core_module.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all), raising=True)


class TestSearchBufferover:
    def test_init_sets_state(self, monkeypatch):
        monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', lambda: 'testkey')
        search = bufferoverun.SearchBufferover('example.com')
        assert search.word == 'example.com'
        assert search.totalhosts == set()
        assert search.totalips == set()
        assert search.proxy is False

    @pytest.mark.asyncio
    async def test_extracts_hostnames_from_results(self, monkeypatch):
        monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', lambda: 'testkey')
        _patch_fetch(
            monkeypatch,
            {
                'Results': [
                    '54.201.204.183,581faa6ff692d0ba8185753570c8624a2a6b4e8e47bd5322216cc12a41def044,,blog.example.com',
                    '104.154.120.133,2122965ac9fa9a2cb9295fc8966569d9a3906995e8fcd61d82d6ec0f9d10dfea,,www.example.com',
                ]
            },
        )
        search = bufferoverun.SearchBufferover('example.com')
        await search.process()
        assert set(await search.get_hostnames()) == {'blog.example.com', 'www.example.com'}

    @pytest.mark.asyncio
    async def test_extracts_ips_from_results(self, monkeypatch):
        monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', lambda: 'testkey')
        _patch_fetch(
            monkeypatch,
            {
                'Results': [
                    '54.201.204.183,581faa6ff692d0ba8185753570c8624a2a6b4e8e47bd5322216cc12a41def044,,blog.example.com',
                    'not-an-ip,hash,,www.example.com',
                ]
            },
        )
        search = bufferoverun.SearchBufferover('example.com')
        await search.process()
        assert set(await search.get_ips()) == {'54.201.204.183'}

    @pytest.mark.asyncio
    async def test_handles_commas_in_cert_org(self, monkeypatch):
        monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', lambda: 'testkey')
        _patch_fetch(monkeypatch, {'Results': ['10.0.0.5,aaabbbcccddd,,,ops.example.com']})
        search = bufferoverun.SearchBufferover('example.com')
        await search.process()
        assert set(await search.get_hostnames()) == {'ops.example.com'}

    @pytest.mark.asyncio
    async def test_empty_response_returns_no_results(self, monkeypatch):
        monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', lambda: 'testkey')
        _patch_fetch(monkeypatch, {})
        search = bufferoverun.SearchBufferover('example.com')
        await search.process()
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()

    @pytest.mark.asyncio
    async def test_failed_fetch_returns_no_results(self, monkeypatch):
        monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', lambda: 'testkey')
        _patch_fetch(monkeypatch, '')
        search = bufferoverun.SearchBufferover('example.com')
        await search.process()
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()
