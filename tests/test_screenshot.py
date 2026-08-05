from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

import theHarvester.screenshot.screenshot as screenshot_module
from theHarvester.screenshot.screenshot import ScreenShotter

if TYPE_CHECKING:
    from pathlib import Path


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

    await ScreenShotter(str(tmp_path)).take_screenshot('www.example.com')

    page.goto.assert_awaited_once_with('https://www.example.com', timeout=35000)
    screenshot_path = page.screenshot.await_args.kwargs['path']
    assert screenshot_path.endswith('www.example.com.png')
