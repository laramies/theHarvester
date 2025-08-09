from _pytest.mark.structures import MarkDecorator
import pytest

from theHarvester.discovery import baidusearch

pytestmark: MarkDecorator = pytest.mark.asyncio


class TestBaiduSearch:
    async def test_process_and_parsing(self, monkeypatch):
        called = {}

        async def fake_fetch_all(urls, headers=None, proxy=False):
            called["urls"] = urls
            called["headers"] = headers
            called["proxy"] = proxy
            return [
                "Contact foo@example.com on a.example.com \n",
                " bar@sub.example.com is here and www.example.com appears \n",
                " Visit sub.a.example.com. baz@example.com \n",
            ]

        # Patch the AsyncFetcher.fetch_all to avoid network I/O
        import theHarvester.lib.core as core_module

        monkeypatch.setattr(core_module.AsyncFetcher, "fetch_all", fake_fetch_all)
        # Make user agent deterministic (not strictly necessary, but stable)
        monkeypatch.setattr(core_module.Core, "get_user_agent", staticmethod(lambda: "UA"), raising=True)

        search = baidusearch.SearchBaidu(word="example.com", limit=21)
        await search.process(proxy=True)

        expected_urls = [
            "https://www.baidu.com/s?wd=%40example.com&pn=0&oq=example.com",
            "https://www.baidu.com/s?wd=%40example.com&pn=10&oq=example.com",
            "https://www.baidu.com/s?wd=%40example.com&pn=20&oq=example.com",
        ]
        assert called["urls"] == expected_urls
        assert called["proxy"] is True

        emails = await search.get_emails()
        hosts = await search.get_hostnames()

        # Ensure our expected values are present
        assert "foo@example.com" in emails
        assert "bar@sub.example.com" in emails
        assert "baz@example.com" in emails

        assert {"a.example.com", "www.example.com", "sub.a.example.com"} <= set(hosts)

    async def test_pagination_limit_exclusive(self, monkeypatch):
        captured = {}

        async def fake_fetch_all(urls, headers=None, proxy=False):
            captured["urls"] = urls
            return [""] * len(urls)

        import theHarvester.lib.core as core_module

        monkeypatch.setattr(core_module.AsyncFetcher, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(core_module.Core, "get_user_agent", staticmethod(lambda: "UA"), raising=True)

        search = baidusearch.SearchBaidu(word="example.com", limit=20)
        await search.process()

        # For limit=20, range(0, 20, 10) yields 0 and 10 only (20 is excluded)
        assert captured["urls"] == [
            "https://www.baidu.com/s?wd=%40example.com&pn=0&oq=example.com",
            "https://www.baidu.com/s?wd=%40example.com&pn=10&oq=example.com",
        ]
