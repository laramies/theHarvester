#!/usr/bin/env python
"""
Created by laramies on 2008-08-21.
Revised to use aiodns & asyncio on 2019-09-23
"""

# Support for Python3.9
from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING

import aiodns

if TYPE_CHECKING:
    from collections.abc import Iterator


class Checker:
    def __init__(self, hosts: list[str], nameservers: list[str]) -> None:
        self.hosts: list[str] = hosts
        self.realhosts: list[str] = []
        self.addresses: set[str] = set()
        self.nameservers: list[str] = nameservers

    # @staticmethod
    # async def query(host, resolver) -> Tuple[str, Any]:
    #     try:
    #         result = await resolver.gethostbyname(host, socket.AF_INET)
    #         addresses = result.addresses
    #         if addresses == [] or addresses is None or result is None:
    #             return f"{host}:", tuple()
    #         else:
    #             return f"{host}:{', '.join(map(str, addresses))}", addresses
    #     except Exception:
    #         return f"{host}", tuple()

    @staticmethod
    async def resolve_host(host: str, resolver: aiodns.DNSResolver) -> str:
        try:
            # TODO add check for ipv6 addrs as well
            result = await resolver.gethostbyname(host, socket.AF_INET)
            addresses_list = result.addresses
            if addresses_list == [] or addresses_list is None or result is None:
                return f'{host}:'
            else:
                addresses_str = ','.join(map(str, list(sorted(set(addresses_list)))))
                return f'{host}:{addresses_str}'
        except Exception:
            return f'{host}:'

    # https://stackoverflow.com/questions/312443/how-do-i-split-a-list-into-equally-sized-chunks
    @staticmethod
    def chunks(lst: list[str], n: int) -> Iterator[list[str]]:
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i : i + n]

    async def query_all(self, resolver: aiodns.DNSResolver, hosts: list[str]) -> list[str]:
        # TODO chunk list into 50 pieces regardless of IPs and subnets
        results: list[str] = await asyncio.gather(*[asyncio.create_task(self.resolve_host(host, resolver)) for host in hosts])
        return results

    async def check(self) -> tuple[list[str], list[str], list[str]]:
        loop = asyncio.get_event_loop()
        resolver = (
            aiodns.DNSResolver(loop=loop, timeout=8)
            if len(self.nameservers) == 0
            else aiodns.DNSResolver(loop=loop, timeout=8, nameservers=self.nameservers)
        )
        all_results: set[str] = set()
        for chunk in self.chunks(self.hosts, 50):
            # TODO split this to get IPs added total ips
            results = await self.query_all(resolver, chunk)
            all_results.update(results)
            for pair in results:
                host, addresses = pair.split(':')
                self.realhosts.append(host)
                # address may be a list of ips; filter out empties
                self.addresses.update({addr for addr in addresses.split(',') if addr})
                # address may be a list of ips
                # and do a set comprehension to remove duplicates
        self.realhosts.sort()
        addresses_list: list[str] = sorted(self.addresses)
        all_results_list: list[str] = sorted(all_results)
        return all_results_list, self.realhosts, addresses_list
