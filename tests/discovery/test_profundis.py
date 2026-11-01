from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import aiohttp
import pytest

from theHarvester.discovery import profundis
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib import core
from theHarvester.lib.source_runner import SourceRequest, run_source


class ProviderStream:
    def __init__(self) -> None:
        self.chunks = [b'{"type":"credits"}\n']
        self.status = 200
        self.error: BaseException | None = None
        self.setup_error: BaseException | None = None
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.options: tuple[Any, ...] = ()
        self.closed = False
        self.response_closed = False
        self.drained = False
        self.headers = {"Content-Type": "text/event-stream"}
        self.content = self

    async def iter_any(self):
        for chunk in self.chunks:
            yield chunk
        if self.error:
            raise self.error
        self.drained = True

    @contextlib.asynccontextmanager
    async def request(self, method: str, url: str, **kwargs: Any):
        self.requests.append((method, url, kwargs))
        if self.setup_error:
            raise self.setup_error
        try:
            yield self
        finally:
            self.response_closed = True

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def stream(monkeypatch: pytest.MonkeyPatch) -> ProviderStream:
    stream = ProviderStream()
    monkeypatch.setattr(core.Core, "api_keys", staticmethod(lambda: {"profundis": {"key": " test-key "}}))

    async def build_session(*args: Any, **kwargs: Any):
        stream.options = args
        return stream

    monkeypatch.setattr(core.AsyncFetcher, "_build_session", build_session)
    return stream


@pytest.mark.provider_contract("profundis")
async def test_real_transport_parses_mixed_fragmented_stream_and_exact_scope(stream: ProviderStream) -> None:
    stream.chunks = [
        b'{"type":"credits","credits":{"balance":100}}\nAPI.WWW.Exa',
        b"mple.COM.\r\napi.www.example.com\nexample.com\nwww.example.com.evil.test\n",
        b'outside.test\nwww.example.com\n{"type":"credits","credits_charged":1}',
    ]
    search = profundis.SearchProfundis("WWW.Example.COM.", None)
    assert await search.process() is None
    assert await search.get_hostnames() == {"api.www.example.com", "www.example.com"}
    assert stream.options[0]["X-API-KEY"] == "test-key"
    assert stream.options[0]["Accept"] == "text/event-stream"
    assert stream.options[1].total == 60
    method, url, kwargs = stream.requests[0]
    assert (method, url) == ("POST", profundis.SearchProfundis.URL)
    assert kwargs["json"] == {"domain": "www.example.com", "max_credits": 10, "source": "theHarvester"}
    assert kwargs["allow_redirects"] is False
    assert len(stream.requests) == 1
    assert stream.drained and stream.closed and stream.response_closed


@pytest.mark.parametrize("key", [None, "", "   "])
def test_missing_key(stream: ProviderStream, monkeypatch: pytest.MonkeyPatch, key: Any) -> None:
    monkeypatch.setattr(core.Core, "api_keys", staticmethod(lambda: {"profundis": {"key": key}}))
    with pytest.raises(MissingKey):
        profundis.SearchProfundis("example.test", 10)
    assert not stream.requests


@pytest.mark.parametrize("budget", [0, -1, 100001, True, "10", 2.5, None])
def test_invalid_budget_fails_before_request(stream: ProviderStream, monkeypatch: pytest.MonkeyPatch, budget: Any) -> None:
    monkeypatch.setattr(core.Core, "api_keys", staticmethod(lambda: {"profundis": {"key": "test-key", "max_credits": budget}}))
    with pytest.raises(ValueError, match="max_credits"):
        profundis.SearchProfundis("example.test", None)
    assert not stream.requests


@pytest.mark.parametrize("limit", [0, -1, True, 2.5])
def test_invalid_result_limit(stream: ProviderStream, limit: Any) -> None:
    with pytest.raises(ValueError, match="limit"):
        profundis.SearchProfundis("example.test", limit)
    assert not stream.requests


async def test_custom_budget_and_result_limit_still_drain_control_records(stream: ProviderStream, monkeypatch) -> None:
    monkeypatch.setattr(core.Core, "api_keys", staticmethod(lambda: {"profundis": {"key": "test-key", "max_credits": 2}}))
    stream.chunks = [b'outside.test\na.example.test\na.example.test\nb.example.test\nc.example.test\n{"type":"credits"}\n']
    search = profundis.SearchProfundis("example.test", 2)
    report = await search.process()
    assert report.status == "completed" and report.stop_reason == "result-limit"
    assert search.totalhosts == {"a.example.test", "b.example.test"}
    assert stream.requests[0][2]["json"]["max_credits"] == 2
    assert stream.drained


@pytest.mark.parametrize(
    ("tail", "reason"),
    [
        (b'{"type":"credits","capped":true,"max_credits":10}', "credit-limit"),
        (b'{"type":"credits"}\n{"code":"Q2014","message":"private account detail"}', "quota-exhausted"),
        (b'{"code":"Q2015"}\n{"type":"credits"}', "usage-limit"),
        (b'{"error":"private account detail"}', "provider-error"),
        (b'{"notice":"private account detail"}', "provider-error"),
        (b'{"code":"UNKNOWN"}', "provider-error"),
        (b'{"unexpected":true}', "invalid-response"),
        (b"{bad json", "invalid-response"),
        (b"[]", "invalid-response"),
        (b"<html>provider failure</html>", "invalid-response"),
        (b"\xff\n", "invalid-response"),
    ],
)
async def test_runner_preserves_partial_results_and_sanitizes_control_records(
    stream: ProviderStream, tail: bytes, reason: str, caplog
) -> None:
    stream.chunks = [b"a.example.test\n", tail]
    outcome = await run_source(SourceRequest("profundis", "example.test", 1, 0, False, True))
    assert outcome.execution.status == "partial"
    assert outcome.execution.stop_reason == reason
    assert {observation.value for observation in outcome.observations} == {"a.example.test"}
    assert "private account detail" not in caplog.text
    assert "test-key" not in caplog.text
    assert stream.closed and stream.response_closed


@pytest.mark.parametrize(
    "status,reason",
    [
        (302, "http-302"),
        (400, "http-400"),
        (401, "access-denied"),
        (402, "quota-exhausted"),
        (403, "access-denied"),
        (429, "http-429"),
        (500, "http-500"),
    ],
)
async def test_http_failures_do_not_retry_or_read_account_data(stream: ProviderStream, status: int, reason: str) -> None:
    stream.status = status
    stream.chunks = [b'{"message":"private account detail"}']
    search = profundis.SearchProfundis("example.test", None)
    report = await search.process()
    assert report.stop_reason == reason
    assert report.status == ("rate-limited" if status == 429 else "failed")
    assert not search.totalhosts and not stream.drained
    assert len(stream.requests) == 1
    assert stream.closed and stream.response_closed


@pytest.mark.parametrize("body", [b"", b"\n", b'{"type":"credits"}\n'])
async def test_valid_empty_result(stream: ProviderStream, body: bytes) -> None:
    stream.chunks = [body]
    search = profundis.SearchProfundis("example.test", None)
    assert await search.process() is None
    assert not search.totalhosts


@pytest.mark.parametrize("failure", ["setup", "body", "cancel", "size"])
async def test_failure_and_cancellation_close_transport_without_retry(stream: ProviderStream, monkeypatch, failure: str) -> None:
    stream.chunks = [b"a.example.test\n"]
    if failure == "setup":
        stream.setup_error = aiohttp.ClientConnectionError("private detail")
    elif failure == "body":
        stream.error = aiohttp.ClientConnectionError("private detail")
    elif failure == "cancel":
        stream.error = asyncio.CancelledError()
    else:
        monkeypatch.setattr(core, "MAX_PROVIDER_STREAM_BYTES", len(stream.chunks[0]))
        stream.chunks.append(b"b.example.test\n")
    search = profundis.SearchProfundis("example.test", None)
    if failure == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await search.process()
    else:
        report = await search.process()
        assert report.stop_reason == ("response-limit" if failure == "size" else "transport-error")
    assert search.totalhosts == (set() if failure == "setup" else {"a.example.test"})
    assert len(stream.requests) == 1 and stream.closed


async def test_proxy_is_used_by_post_transport(stream: ProviderStream, monkeypatch) -> None:
    monkeypatch.setattr(
        core.AsyncFetcher, "_get_random_proxy", staticmethod(lambda proxies: ("http://proxy.example:8080", "http"))
    )
    monkeypatch.setattr(core.AsyncFetcher, "proxy_list", property(lambda self: []))
    await profundis.SearchProfundis("example.test", None).process(proxy=True)
    assert stream.options[2:4] == ("http://proxy.example:8080", "http")
    assert stream.requests[0][2]["proxy"] == "http://proxy.example:8080"


async def test_missing_proxy_never_falls_back_to_direct(stream: ProviderStream, monkeypatch) -> None:
    monkeypatch.setattr(core.AsyncFetcher, "_get_random_proxy", staticmethod(lambda proxies: (None, None)))
    monkeypatch.setattr(core.AsyncFetcher, "proxy_list", property(lambda self: []))
    with pytest.raises(core.ProxyUnavailableError):
        await profundis.SearchProfundis("example.test", None).process(proxy=True)
    assert not stream.requests
