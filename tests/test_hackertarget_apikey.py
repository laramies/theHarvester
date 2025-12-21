import pytest
from theHarvester.discovery import hackertarget as ht_mod
from theHarvester.lib.core import Core


class TestHackerTargetApiKey:

    @pytest.mark.asyncio
    async def test_do_search_with_apikey(self, monkeypatch):
        # make Core.hackertarget_key return a known key
        monkeypatch.setattr(Core, "hackertarget_key", lambda: "TESTKEY")

        # monkeypatch AsyncFetcher.fetch_all to capture requested URLs
        async def fake_fetch_all(urls, headers=None, proxy=False):
            # ensure apikey present in each URL
            assert all("apikey=TESTKEY" in u for u in urls)
            return ["1.2.3.4,host.example.com\n", "No PTR records found\n"]

        monkeypatch.setattr(ht_mod.AsyncFetcher, "fetch_all", fake_fetch_all)

        s = ht_mod.SearchHackerTarget("example.com")
        await s.do_search()

        # after do_search, total_results should include our fake response (commas replaced by colons)
        assert "1.2.3.4:host.example.com" in s.total_results

    @pytest.mark.asyncio
    async def test_do_search_without_apikey(self, monkeypatch):
        monkeypatch.setattr(Core, "hackertarget_key", lambda: None)

        async def fake_fetch_all(urls, headers=None, proxy=False):
            assert all("apikey=" not in u for u in urls)
            return ["1.2.3.4,host.example.com\n"]

        monkeypatch.setattr(ht_mod.AsyncFetcher, "fetch_all", fake_fetch_all)

        s = ht_mod.SearchHackerTarget("example.com")
        await s.do_search()
        assert "1.2.3.4:host.example.com" in s.total_results
