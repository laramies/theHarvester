from __future__ import annotations

import pytest

from theHarvester.screenshot import screenshot


@pytest.mark.parametrize(
    ('platform', 'expected_separator'),
    [
        ('darwin', '/'),
        ('linux', '/'),
        ('win32', '\\'),
    ],
)
def test_screenshot_output_separator_matches_platform(monkeypatch, platform: str, expected_separator: str) -> None:
    monkeypatch.setattr(screenshot.sys, 'platform', platform)

    shotter = screenshot.ScreenShotter('screenshots')

    assert shotter.slash == expected_separator
