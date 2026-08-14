#!/usr/bin/env python
"""Created by laramies on 2008-08-21.
Revised to use aiodns & asyncio on 2019-09-23
"""

# Support for Python3.9
from __future__ import annotations

import asyncio
import inspect
import ipaddress
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING

import aiodns

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(frozen=True)
class HostDnsRecords:
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()

    @property
    def addresses(self) -> tuple[str, ...]:
        return self.ipv4 + self.ipv6


def is_expected_dns_absence(error: BaseException) -> bool:
    return (
        isinstance(error, aiodns.error.DNSError)
        and bool(error.args)
        and error.args[0] in {aiodns.error.ARES_ENODATA, aiodns.error.ARES_ENOTFOUND}
    )


async def resolve_ip_addresses(hostname: str, *, family: socket.AddressFamily = socket.AF_UNSPEC) -> tuple[str, ...]:
    """Resolve every unique IP address for a hostname."""
    resolver = aiodns.DNSResolver()
    try:
        answer = await resolver.getaddrinfo(hostname, family=family)
    finally:
        close = getattr(resolver, 'close', None)
        if close is not None:
            close_result = close()
            if inspect.isawaitable(close_result):
                await close_result

    addresses: set[str] = set()
    for node in answer.nodes:
        try:
            value = node.addr[0]
            if isinstance(value, bytes):
                value = value.decode('ascii')
            address = ipaddress.ip_address(value)
        except (AttributeError, IndexError, TypeError, UnicodeDecodeError, ValueError):
            continue
        if family == socket.AF_INET and address.version != 4:
            continue
        if family == socket.AF_INET6 and address.version != 6:
            continue
        addresses.add(str(address))
    return tuple(sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))))


class Checker:
    """Resolve hosts while preserving the legacy ``check()`` return tuple.

    Normalized A, AAAA, and CNAME values are available in ``records``.
    CNAME-only hosts retain the existing plain-host string form.
    """

    def __init__(self, hosts: list[str], nameservers: list[str]) -> None:
        self.hosts: list[str] = hosts
        self.realhosts: list[str] = []
        self.addresses: set[str] = set()
        self.records: dict[str, HostDnsRecords] = {}
        self.nameservers: list[str] = nameservers
        self.query_error_count = 0
        self.query_error_types: set[str] = set()

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

    async def resolve_host(self, host: str, resolver: aiodns.DNSResolver) -> tuple[str, HostDnsRecords] | None:
        record_types = ('A', 'AAAA', 'CNAME')
        results = await asyncio.gather(
            *(resolver.query_dns(host, record_type) for record_type in record_types),
            return_exceptions=True,
        )
        values: dict[str, set[str]] = {record_type: set() for record_type in record_types}
        for record_type, result in zip(record_types, results, strict=True):
            if isinstance(result, BaseException):
                if isinstance(result, Exception):
                    if not is_expected_dns_absence(result):
                        self.query_error_count += 1
                        self.query_error_types.add(type(result).__name__)
                    continue
                raise result
            for record in result.answer:
                value = getattr(record.data, 'cname' if record_type == 'CNAME' else 'addr', None)
                if value is None:
                    continue
                if record_type == 'CNAME':
                    if normalized := value.rstrip('.').lower():
                        values[record_type].add(normalized)
                    continue
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if address.version == (4 if record_type == 'A' else 6):
                    values[record_type].add(str(address))
        records = HostDnsRecords(
            ipv4=tuple(sorted(values['A'])),
            ipv6=tuple(sorted(values['AAAA'])),
            cnames=tuple(sorted(values['CNAME'])),
        )
        return (host, records) if records.addresses or records.cnames else None

    # https://stackoverflow.com/questions/312443/how-do-i-split-a-list-into-equally-sized-chunks
    @staticmethod
    def chunks(lst: list[str], n: int) -> Iterator[list[str]]:
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i : i + n]

    async def query_all(self, resolver: aiodns.DNSResolver, hosts: list[str]) -> list[tuple[str, HostDnsRecords] | None]:
        # TODO chunk list into 50 pieces regardless of IPs and subnets
        results = await asyncio.gather(*[asyncio.create_task(self.resolve_host(host, resolver)) for host in hosts])
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
            for result in results:
                if result is None:
                    continue
                host, records = result
                self.records[host] = records
                all_results.add(f'{host}:{",".join(records.addresses)}' if records.addresses else host)
                self.realhosts.append(host)
                # address may be a list of ips; filter out empties
                self.addresses.update(records.addresses)
                # address may be a list of ips
                # and do a set comprehension to remove duplicates
        self.realhosts.sort()
        addresses_list: list[str] = sorted(self.addresses)
        all_results_list: list[str] = sorted(all_results)
        return all_results_list, self.realhosts, addresses_list
