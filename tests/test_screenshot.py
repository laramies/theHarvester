from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

import theHarvester.screenshot.screenshot as screenshot_module
from theHarvester.screenshot.screenshot import ScreenShotter


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


@pytest.mark.parametrize(
    ('target', 'filename'),
    [
        ('https://www.example.com:8443/login?next=/admin', 'www.example.com_8443.png'),
        ('2001:db8::1', '2001_db8__1.png'),
    ],
)
def test_screenshot_path_uses_the_target_host_and_port(tmp_path: Path, target: str, filename: str) -> None:
    screenshotter = ScreenShotter(str(tmp_path))

    assert screenshotter.screenshot_path(target) == tmp_path / filename


@pytest.mark.parametrize(
    ('target', 'response_url', 'request_url'),
    [
        ('www.example.com', 'https://www.example.com/landing', 'https://www.example.com'),
        ('2001:db8::1', 'https://[2001:db8::1]/', 'https://[2001:db8::1]'),
    ],
)
@pytest.mark.asyncio
async def test_visit_prefers_https_and_normalizes_the_target(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    response_url: str,
    request_url: str,
) -> None:
    response = MagicMock()
    response.url = response_url
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
    result = await ScreenShotter.visit(target)

    assert result == (response_url, 'reachable')
    assert session.get.call_args.args[0] == request_url


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
    result = await ScreenShotter.visit('www.example.com')

    assert result == ('http://www.example.com', 'reachable')
    assert [call.args[0] for call in session.get.call_args_list] == [
        'https://www.example.com',
        'http://www.example.com',
    ]


@pytest.mark.parametrize(
    ('target', 'normalized_url', 'filename'),
    [
        ('www.example.com', 'https://www.example.com', 'www.example.com.png'),
        ('2001:db8::1', 'https://[2001:db8::1]', '2001_db8__1.png'),
    ],
)
@pytest.mark.asyncio
async def test_take_screenshot_normalizes_the_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
    normalized_url: str,
    filename: str,
) -> None:
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
    monkeypatch.setattr(screenshot_module.os, 'chmod', MagicMock())

    captured_url = await ScreenShotter(str(tmp_path)).take_screenshot(target)

    assert captured_url == normalized_url
    page.goto.assert_awaited_once_with(normalized_url, timeout=35000)
    screenshot_path = page.screenshot.await_args.kwargs['path']
    assert Path(screenshot_path) == tmp_path / filename


@pytest.mark.asyncio
async def test_take_screenshot_can_name_the_artifact_for_the_authorized_subject(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
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
    monkeypatch.setattr(screenshot_module.os, 'chmod', MagicMock())
    output_path = tmp_path / 'authorized.example.com.png'

    captured_url = await ScreenShotter(str(tmp_path)).take_screenshot(
        'https://login.example.net/session',
        output_path=output_path,
    )

    assert captured_url == 'https://login.example.net/session'
    assert page.screenshot.await_args.kwargs['path'] == output_path


@pytest.mark.asyncio
async def test_screenshot_visit_uses_an_http_proxy(monkeypatch) -> None:
    response = MagicMock()
    response.url = 'https://example.com'
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

    result = await ScreenShotter.visit('example.com', proxy='http://proxy.example:8080')

    assert result == ('https://example.com', 'reachable')
    assert session.get.call_args.kwargs == {'proxy': 'http://proxy.example:8080'}


@pytest.mark.asyncio
async def test_screenshot_capture_is_owner_only(tmp_path, monkeypatch) -> None:
    class Page:
        async def goto(self, *_args, **_kwargs):
            return None

        async def screenshot(self, *, path):
            Path(path).write_bytes(b'png')  # noqa: ASYNC240 - tiny in-memory browser fixture

        async def close(self):
            return None

    class Context:
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

    monkeypatch.setattr(screenshot_module, 'async_playwright', Playwright)

    await ScreenShotter(str(tmp_path)).take_screenshot('example.com')

    assert stat.S_IMODE((tmp_path / 'example.com.png').stat().st_mode) == 0o600
