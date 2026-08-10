import pytest

from theHarvester.discovery import zoomeyesearch


@pytest.mark.asyncio
async def test_banner_urls_are_absolute_http_and_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', staticmethod(lambda: 'test-key'))
    search = zoomeyesearch.SearchZoomEye('example.com', 1)
    banner = '\n'.join(
        f'"{value}"'
        for value in (
            'https://api.example.com/v1',
            '//example.com/path',
            '/assets/example.com/config.js',
            'https://evil.test/?target=example.com',
            'ftp://api.example.com/archive',
        )
    )

    _hostnames, _emails, _ips, _asns, urls = await search.parse_matches([{'service': {'banner': banner}}])

    assert urls == {'https://api.example.com/v1'}
