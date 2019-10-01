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
            return result
        except Exception:
            # print(f'An error occurred in query: {e}')
            return f"{host}:"

    async def query_all(self, resolver) -> list:
        results = await asyncio.gather(*[asyncio.create_task(self.query(host, resolver))
                                         for host in self.hosts])
        return results

    async def check(self):
        import pprint as p
        p.pprint(self.hosts, indent=4)

        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop)
        results = await self.query_all(resolver)
        print('results: ', results)
        import pprint as p
        p.pprint(results, indent=4)

        #loop.close()
        return self.realhosts

    """
    def check(self):
        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop)
        for host in self.hosts:
            resp = self.query(host, resolver)
            result = loop.run_until_complete(resp)
            true_result = ''
            if isinstance(result, str):
                true_result = result
            elif result != '' and not isinstance(result, str) and result.addresses is not None \
                    and result.addresses != []:
                result = result.addresses
                result.sort()
                true_result = f"{host}:{', '.join(map(str, result))}"
            self.realhosts.append(true_result)
        loop.close()
        return self.realhosts
    """
