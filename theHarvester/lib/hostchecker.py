#!/usr/bin/env python
# encoding: utf-8
"""
Created by laramies on 2008-08-21.
Revised to use aiodns & asyncio on 2019-09-23
"""

import aiodns
import asyncio
import socket
from typing import Tuple, Any, List, Set


class Checker:

    def __init__(self, hosts: list, nameserver: bool = False) -> None:
        self.hosts = hosts
        self.realhosts: List = []
        self.addresses: Set = set()
        self.nameserver: List = []
        if nameserver:
            self.nameserver = nameserver

    @staticmethod
    async def query(host, resolver) -> Tuple[str, Any]:
        try:
            result = await resolver.gethostbyname(host, socket.AF_INET)
            addresses = result.addresses
            if addresses == [] or addresses is None or result is None:
                return f"{host}:", tuple()
            else:
                return f"{host}:{', '.join(map(str, addresses))}", addresses
        except Exception:
            return f"{host}", tuple()

    async def query_all(self, resolver) -> tuple[
            BaseException | Any, BaseException | Any, BaseException | Any, BaseException | Any, BaseException | Any]:
        results = await asyncio.gather(*[asyncio.create_task(self.query(host, resolver))
                                         for host in self.hosts])
        return results

    async def check(self):
        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop, timeout=4) if len(self.nameserver) == 0\
            else aiodns.DNSResolver(loop=loop, timeout=4, nameservers=self.nameserver)
        results = await self.query_all(resolver)
        for host, address in results:
            self.realhosts.append(host)
            self.addresses.update({addr for addr in address})
            # address may be a list of ips
            # and do a set comprehension to remove duplicates
        self.realhosts.sort()
        self.addresses = list(self.addresses)
        return self.realhosts, self.addresses
