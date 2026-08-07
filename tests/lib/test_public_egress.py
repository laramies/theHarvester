import socket

import pytest

from theHarvester.lib.public_egress import PublicResolver


@pytest.mark.asyncio
async def test_public_resolver_rejects_non_global_addresses_and_pins_dns(monkeypatch) -> None:
    from theHarvester.lib import public_egress

    real_ip_address = public_egress.ipaddress.ip_address

    def fixture_ip_address(value):
        address = real_ip_address(value)
        if str(address) == '192.0.2.1':
            return type('PublicTestAddress', (), {'version': 4, 'is_global': True, 'is_multicast': False})()
        return address

    monkeypatch.setattr(public_egress.ipaddress, 'ip_address', fixture_ip_address)

    class ChangingLoop:
        def __init__(self) -> None:
            self.calls = 0

        async def getaddrinfo(self, host, port, *, type, family):
            self.calls += 1
            address = '192.0.2.1' if self.calls == 1 else '127.0.0.1'
            return [(socket.AF_INET, type, socket.IPPROTO_TCP, host, (address, port))]

    loop = ChangingLoop()
    monkeypatch.setattr(public_egress.asyncio, 'get_running_loop', lambda: loop)
    resolver = PublicResolver()

    first = await resolver.resolve('example.com', 443)
    second = await resolver.resolve('example.com', 443)

    assert [entry['host'] for entry in first] == ['192.0.2.1']
    assert second == first
    assert loop.calls == 1

    private_resolver = PublicResolver()
    with pytest.raises(OSError, match='non-public address'):
        await private_resolver.resolve('100.64.0.1', 80)

    multicast_resolver = PublicResolver()
    with pytest.raises(OSError, match='non-public address'):
        await multicast_resolver.resolve('224.0.0.1', 80)
