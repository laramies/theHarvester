#!/usr/bin/env python
# encoding: utf-8
"""
Created by laramies on 2008-08-21.
Revised to use aiodns & asyncio on 2019-09-23
"""

import aiodns
import asyncio
import socket


class Checker:

    def __init__(self, hosts: list):
        self.hosts = hosts
        self.realhosts = []

    @staticmethod
    async def query(host, resolver) -> [list, str]:
        try:
            result = await resolver.gethostbyname(host, socket.AF_INET)
            addresses = result.addresses
            if addresses == [] or addresses is None or result is None:
                return f"{host}:"
            else:
                return f"{host}:{', '.join(map(str, addresses))}"
            # return result
        except Exception:
            # print(f'An error occurred in query: {e}')
            return f"{host}:"

    async def query_all(self, resolver) -> list:
        results = await asyncio.gather(*[asyncio.create_task(self.query(host, resolver))
                                         for host in self.hosts])
        return results

    async def check(self):
        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop)
        results = await self.query_all(resolver)
        self.realhosts = [result for result in results]
        self.realhosts.sort()
        return self.realhosts
