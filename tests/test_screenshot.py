from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

import theHarvester.screenshot.screenshot as screenshot_module
from theHarvester.screenshot.screenshot import ScreenShotter


class PublicResolver:
    async def resolve(self, *_args, **_kwargs):
        return [{'host': '192.0.2.1'}]


@pytest.mark.parametrize(
    ('platform', 'expected_separator'),
    [('darwin', '/'), ('linux', '/'), ('win32', '\\')],
)
def test_screenshot_output_separator_matches_platform(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    expected_separator: str,
) -> None:
    monkeypatch.setattr(screenshot_module.sys, 'platform', platform)

    assert ScreenShotter('screenshots').slash == expected_separator


@pytest.mark.asyncio
async def test_visit_prefers_https_and_returns_final_www_url(monkeypatch: pytest.MonkeyPatch) -> None:
    response = MagicMock()
    response.url = 'https://www.example.com/landing'
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=False)
    response.text = AsyncMock(return_value='reachable')
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.get.return_value = response
    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', MagicMock(return_value=session))
    monkeypatch.setattr(screenshot_module.aiohttp, 'TCPConnector', MagicMock())
    monkeypatch.setattr(screenshot_module.ssl, 'create_default_context', MagicMock())
    monkeypatch.setattr(screenshot_module, 'PublicResolver', PublicResolver)

    result = await ScreenShotter.visit('www.example.com')

    assert result == ('https://www.example.com/landing', 'reachable')
    assert session.get.call_args.args[0] == 'https://www.example.com'


@pytest.mark.asyncio
async def test_visit_falls_back_to_http_when_https_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    response = MagicMock()
    response.url = 'http://www.example.com'
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=False)
    response.text = AsyncMock(return_value='reachable')
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.get.side_effect = [screenshot_module.aiohttp.ClientError('TLS unavailable'), response]
    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', MagicMock(return_value=session))
    monkeypatch.setattr(screenshot_module.aiohttp, 'TCPConnector', MagicMock())
    monkeypatch.setattr(screenshot_module.ssl, 'create_default_context', MagicMock())
    monkeypatch.setattr(screenshot_module, 'PublicResolver', PublicResolver)

    result = await ScreenShotter.visit('www.example.com')

    assert result == ('http://www.example.com', 'reachable')
    assert [call.args[0] for call in session.get.call_args_list] == [
        'https://www.example.com',
        'http://www.example.com',
    ]


@pytest.mark.asyncio
async def test_take_screenshot_preserves_www_hostname(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    page = AsyncMock()
    context = AsyncMock()
    context.new_page.return_value = page
    browser = AsyncMock()
    browser.new_context.return_value = context
    playwright = MagicMock()
    playwright.chromium.launch = AsyncMock(return_value=browser)
    manager = MagicMock()
    manager.__aenter__ = AsyncMock(return_value=playwright)
    manager.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(screenshot_module, 'async_playwright', MagicMock(return_value=manager))
    monkeypatch.setattr(screenshot_module, 'PublicResolver', PublicResolver)
    monkeypatch.setattr(screenshot_module.os, 'chmod', MagicMock())

    captured_url = await ScreenShotter(str(tmp_path)).take_screenshot('www.example.com')

    assert captured_url == 'https://www.example.com'
    page.goto.assert_awaited_once_with('https://www.example.com', timeout=35000)
    screenshot_path = page.screenshot.await_args.kwargs['path']
    assert screenshot_path.endswith('www.example.com.png')


@pytest.mark.asyncio
async def test_screenshot_visit_rejects_a_non_public_discovered_host(monkeypatch) -> None:
    sessions = []

    def unexpected_session(*_args, **_kwargs):
        sessions.append(True)
        raise AssertionError('HTTP session should not be created')

    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', unexpected_session)

    result = await ScreenShotter.visit('100.64.0.1')

    assert result == ('', '')
    assert sessions == []


@pytest.mark.asyncio
async def test_screenshot_visit_refuses_an_unpinned_proxy(monkeypatch) -> None:
    sessions = []

    def unexpected_session(*_args, **_kwargs):
        sessions.append(True)
        raise AssertionError('HTTP session should not be created')

    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', unexpected_session)

    result = await ScreenShotter.visit('192.0.2.1', proxy='http://proxy.example:8080')

    assert result == ('', '')
    assert sessions == []


@pytest.mark.asyncio
async def test_screenshot_visit_does_not_follow_redirects(monkeypatch) -> None:
    requests = []

    class Resolver:
        async def resolve(self, *_args, **_kwargs):
            return [{'host': '192.0.2.1'}]

    class Response:
        url = 'https://example.com'

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def text(self, _encoding):
            return 'fixture'

    class Session:
        def __init__(self, **_kwargs):
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def get(self, url, **kwargs):
            requests.append((url, kwargs))
            return Response()

    monkeypatch.setattr(screenshot_module, 'PublicResolver', Resolver)
    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', Session)
    monkeypatch.setattr(screenshot_module.aiohttp, 'TCPConnector', lambda **_kwargs: object())
    monkeypatch.setattr(screenshot_module.ssl, 'create_default_context', lambda **_kwargs: object())

    result = await ScreenShotter.visit('example.com')

    assert result == ('https://example.com', 'fixture')
    assert requests == [('https://example.com', {'allow_redirects': False})]


@pytest.mark.asyncio
async def test_screenshot_capture_rejects_a_non_public_discovered_host(monkeypatch) -> None:
    launches = []

    def unexpected_playwright():
        launches.append(True)
        raise AssertionError('Playwright should not launch')

    monkeypatch.setattr(screenshot_module, 'async_playwright', unexpected_playwright)

    await ScreenShotter('/tmp/wayfinder').take_screenshot('100.64.0.1')

    assert launches == []


@pytest.mark.asyncio
async def test_screenshot_capture_is_owner_only(tmp_path, monkeypatch) -> None:
    websocket_closes = []

    class Resolver:
        async def resolve(self, *_args, **_kwargs):
            return [{'host': '192.0.2.1'}]

    class Page:
        async def goto(self, *_args, **_kwargs):
            return None

        async def screenshot(self, *, path):
            Path(path).write_bytes(b'png')  # noqa: ASYNC240 - tiny in-memory browser fixture

        async def close(self):
            return None

    class Context:
        async def route(self, *_args, **_kwargs):
            return None

        async def route_web_socket(self, _pattern, handler):
            class WebSocket:
                async def close(self, **_kwargs):
                    websocket_closes.append(True)

            await handler(WebSocket())

        async def new_page(self):
            return Page()

        async def close(self):
            return None

    class Browser:
        async def new_context(self):
            return Context()

        async def close(self):
            return None

    class Playwright:
        chromium = None

        def __init__(self):
            self.chromium = self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def launch(self, **_kwargs):
            return Browser()

    monkeypatch.setattr(screenshot_module, 'PublicResolver', Resolver)
    monkeypatch.setattr(screenshot_module, 'async_playwright', Playwright)

    await ScreenShotter(str(tmp_path)).take_screenshot('example.com')

    assert stat.S_IMODE((tmp_path / 'example.com.png').stat().st_mode) == 0o600
    assert websocket_closes == [True]
