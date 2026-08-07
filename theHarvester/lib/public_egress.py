from __future__ import annotations

import asyncio
import ipaddress
import socket

from aiohttp.abc import AbstractResolver, ResolveResult


class PublicResolver(AbstractResolver):
    """Resolve and pin hosts only when every address is globally routable."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, int, socket.AddressFamily], list[ResolveResult]] = {}

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[ResolveResult]:
        key = (host, port, family)
        if key in self._cache:
            return self._cache[key]
        try:
            address = ipaddress.ip_address(host)
            addresses = [(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.IPPROTO_TCP, str(address))]
        except ValueError:
            addresses = [
                (resolved_family, proto, socket_address[0])
                for resolved_family, _, proto, _, socket_address in await asyncio.get_running_loop().getaddrinfo(
                    host,
                    port,
                    type=socket.SOCK_STREAM,
                    family=family,
                )
            ]
        results: list[ResolveResult] = []
        seen: set[str] = set()
        for resolved_family, proto, resolved_host in addresses:
            if resolved_host in seen:
                continue
            seen.add(resolved_host)
            address = ipaddress.ip_address(resolved_host)
            if not address.is_global or address.is_multicast:
                raise OSError(f'Refusing non-public address for {host}')
            results.append(
                ResolveResult(
                    hostname=host,
                    host=resolved_host,
                    port=port,
                    family=resolved_family,
                    proto=proto,
                    flags=socket.AI_NUMERICHOST,
                )
            )
        if not results:
            raise OSError(f'No public address found for {host}')
        self._cache[key] = results
        return results

    async def close(self) -> None:
        return None
