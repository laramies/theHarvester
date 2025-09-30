import requests
from theHarvester.discovery import hackertarget as ht_mod

class DummyResp:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code
    def raise_for_status(self):
        if self.status_code != 200:
            raise requests.HTTPError()

def test_append_apikey_to_url():
    base = "https://api.hackertarget.com/hostsearch/?q=example.com"
    out = ht_mod._append_apikey_to_url(base, "MYKEY")
    assert "apikey=MYKEY" in out

def test_do_search_with_apikey(monkeypatch):
    # make _get_hackertarget_key return a known key
    monkeypatch.setattr(ht_mod, "_get_hackertarget_key", lambda: "TESTKEY")

    # monkeypatch AsyncFetcher.fetch_all to capture requested URLs
    async def fake_fetch_all(urls, headers=None, proxy=False):
        # ensure apikey present in each URL
        assert all(("apikey=TESTKEY" in u or "apikey=TESTKEY" in (u.split("?", 1)[1] if "?" in u else "")) for u in urls)
        return ["1.2.3.4,host.example.com\n", "No PTR records found\n"]

    monkeypatch.setattr(ht_mod.AsyncFetcher, "fetch_all", fake_fetch_all)

    s = ht_mod.SearchHackerTarget("example.com")

    # run the coroutine
    import asyncio
    asyncio.get_event_loop().run_until_complete(s.do_search())

    # after do_search, total_results should include our fake response (commas replaced by colons)
    assert "1.2.3.4:host.example.com" in s.total_results

def test_do_search_without_apikey(monkeypatch):
    monkeypatch.setattr(ht_mod, "_get_hackertarget_key", lambda: None)

    async def fake_fetch_all(urls, headers=None, proxy=False):
        assert all("apikey=" not in u for u in urls)
        return ["1.2.3.4,host.example.com\n"]

    monkeypatch.setattr(ht_mod.AsyncFetcher, "fetch_all", fake_fetch_all)

    s = ht_mod.SearchHackerTarget("example.com")
    import asyncio
    asyncio.get_event_loop().run_until_complete(s.do_search())
    assert "1.2.3.4:host.example.com" in s.total_results
