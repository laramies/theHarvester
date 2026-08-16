#!/usr/bin/env python
"""Created by laramies on 2008-08-21.
Revised to use aiodns & asyncio on 2019-09-23
"""

# Support for Python3.9
from __future__ import annotations

import asyncio
import inspect
import ipaddress
import math
import socket
from dataclasses import dataclass

import aiodns

from theHarvester.lib.cancellation import drain_tasks_after_cancellation

DEFAULT_DNS_CONCURRENCY = 20
DEFAULT_DNS_REQUEST_LIMIT = None
DEFAULT_DNS_RUNTIME_SECONDS = None


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

    def __init__(
        self,
        hosts: list[str],
        nameservers: list[str],
        *,
        concurrency: int = DEFAULT_DNS_CONCURRENCY,
        request_limit: int | None = DEFAULT_DNS_REQUEST_LIMIT,
        runtime_seconds: float | None = DEFAULT_DNS_RUNTIME_SECONDS,
    ) -> None:
        if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency <= 0:
            raise ValueError('DNS concurrency must be a positive integer')
        if request_limit is not None and (
            isinstance(request_limit, bool) or not isinstance(request_limit, int) or request_limit <= 0
        ):
            raise ValueError('DNS request limit must be a positive integer')
        if runtime_seconds is not None and (
            isinstance(runtime_seconds, bool)
            or not isinstance(runtime_seconds, (int, float))
            or not math.isfinite(runtime_seconds)
            or runtime_seconds <= 0
        ):
            raise ValueError('DNS runtime must be a positive finite number')
        self.hosts = list(dict.fromkeys(host.strip().lower().rstrip('.') for host in hosts if host.strip().rstrip('.')))
        self.realhosts: list[str] = []
        self.addresses: set[str] = set()
        self.records: dict[str, HostDnsRecords] = {}
        self.nameservers: list[str] = nameservers
        self.concurrency = concurrency
        self.request_limit = request_limit
        self.runtime_seconds = runtime_seconds
        self.request_count = 0
        self.completed_count = 0
        self.stop_reason: str | None = None
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

    async def query_all(self, resolver: aiodns.DNSResolver, hosts: list[str]) -> list[tuple[str, HostDnsRecords] | None]:
        jobs = iter(hosts)
        results: list[tuple[str, HostDnsRecords] | None] = []
        tasks: list[asyncio.Task[None]] = []
        primary_cancellation: asyncio.CancelledError | None = None

        async def worker() -> None:
            nonlocal primary_cancellation
            try:
                for host in jobs:
                    if self.request_limit is not None and self.request_count + 3 > self.request_limit:
                        self.stop_reason = 'query-limit'
                        return
                    self.request_count += 3
                    result = await self.resolve_host(host, resolver)
                    results.append(result)
                    self.completed_count += 1
                    if result is not None:
                        self._accept_result(*result)
            except asyncio.CancelledError as error:
                if primary_cancellation is None:
                    primary_cancellation = error
                current_task = asyncio.current_task()
                for task in tasks:
                    if task is not current_task and not task.done():
                        task.cancel()
                raise

        async with asyncio.TaskGroup() as group:
            for index in range(min(self.concurrency, len(hosts))):
                tasks.append(group.create_task(worker(), name=f'dns-resolve:{index}'))
        if primary_cancellation is not None:
            raise primary_cancellation
        return results

    def _accept_result(self, host: str, records: HostDnsRecords) -> None:
        self.records[host] = records
        self.realhosts.append(host)
        self.addresses.update(records.addresses)

    def snapshot(self) -> tuple[list[str], list[str], list[str]]:
        realhosts = sorted(self.realhosts)
        resolved = sorted(
            f'{host}:{",".join(self.records[host].addresses)}' if self.records[host].addresses else host for host in realhosts
        )
        return resolved, realhosts, sorted(self.addresses)

    async def check(self) -> tuple[list[str], list[str], list[str]]:
        loop = asyncio.get_running_loop()
        resolver = (
            aiodns.DNSResolver(loop=loop, timeout=8)
            if len(self.nameservers) == 0
            else aiodns.DNSResolver(loop=loop, timeout=8, nameservers=self.nameservers)
        )
        phase_error: BaseException | None = None
        try:
            try:
                if self.runtime_seconds is None:
                    await self.query_all(resolver, self.hosts)
                else:
                    async with asyncio.timeout(self.runtime_seconds):
                        await self.query_all(resolver, self.hosts)
            except TimeoutError:
                self.stop_reason = 'runtime-limit'
        except BaseException as error:
            phase_error = error
        cleanup_interruptions: tuple[asyncio.CancelledError, ...] = ()
        close_error: BaseException | None = None
        if close := getattr(resolver, 'close', None):
            close_task = asyncio.create_task(close(), name='dns-resolver-close')
            cleanup_interruptions = await drain_tasks_after_cancellation((close_task,), cancel=False)
            if close_task.cancelled():
                close_error = asyncio.CancelledError('DNS resolver close cancelled')
            else:
                close_error = close_task.exception()
        if isinstance(phase_error, asyncio.CancelledError):
            raise phase_error
        if cleanup_interruptions:
            raise cleanup_interruptions[0]
        if phase_error is not None:
            raise phase_error
        if close_error is not None:
            raise close_error
        return self.snapshot()
