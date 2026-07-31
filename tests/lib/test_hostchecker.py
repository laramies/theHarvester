from types import SimpleNamespace

import pytest

from theHarvester.lib import hostchecker


@pytest.mark.asyncio
async def test_checker_normalizes_byte_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        def __init__(self, **_kwargs: object) -> None:
            return None

        async def getaddrinfo(self, _host: str, _family: int) -> SimpleNamespace:
            return SimpleNamespace(nodes=[SimpleNamespace(addr=(b'192.0.2.10', 0))])

    monkeypatch.setattr(hostchecker.aiodns, 'DNSResolver', FakeResolver)

    resolved, hosts, addresses = await hostchecker.Checker(
        ['www.example.com'],
        ['192.0.2.53'],
    ).check()

    assert resolved == ['www.example.com:192.0.2.10']
    assert hosts == ['www.example.com']
    assert addresses == ['192.0.2.10']
