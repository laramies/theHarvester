#!/usr/bin/env python
"""
Created by laramies on 2008-08-21.
Revised to use aiodns & asyncio on 2019-09-23
"""

# Support for Python3.9
from __future__ import annotations

import asyncio
import socket
from typing import Any

import aiodns


class Checker:
    def __init__(self, hosts: list, nameserver: list) -> None:
        self.hosts = hosts
        self.realhosts: list = []
        self.addresses: set = set()
        self.nameserver = nameserver

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
    async def resolve_host(host, resolver) -> str:
        try:
            # TODO add check for ipv6 addrs as well
            result = await resolver.gethostbyname(host, socket.AF_INET)
            addresses = result.addresses
            if addresses == [] or addresses is None or result is None:
                return f'{host}:'
            else:
                addresses = ','.join(map(str, list(sorted(set(addresses)))))
                # addresses = list(sorted(addresses))
                return f'{host}:{addresses}'
        except Exception:
            return f'{host}:'

    # https://stackoverflow.com/questions/312443/how-do-i-split-a-list-into-equally-sized-chunks
    @staticmethod
    def chunks(lst, n):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i : i + n]

    async def query_all(self, resolver, hosts) -> list[Any]:
        # TODO chunk list into 50 pieces regardless of IPs and subnets
        results = await asyncio.gather(*[asyncio.create_task(self.resolve_host(host, resolver)) for host in hosts])
        return results

    async def check(self):
        loop = asyncio.get_event_loop()
        resolver = (
            aiodns.DNSResolver(loop=loop, timeout=8)
            if len(self.nameserver) == 0
            else aiodns.DNSResolver(loop=loop, timeout=8, nameservers=self.nameserver)
        )
        all_results = set()
        for chunk in self.chunks(self.hosts, 50):
            # TODO split this to get IPs added total ips
            results = await self.query_all(resolver, chunk)
            all_results.update(results)
            for pair in results:
                host, addresses = pair.split(':')
                self.realhosts.append(host)
                self.addresses.update({addr for addr in addresses.split(',')})
                # address may be a list of ips
                # and do a set comprehension to remove duplicates
        self.realhosts.sort()
        self.addresses = list(self.addresses)
        all_results = list(sorted(all_results))
        return all_results, self.realhosts, self.addresses
