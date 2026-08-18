"""DNS brute-force and reverse-lookup helpers."""

import asyncio
import logging
import math
import re
import sys
from dataclasses import dataclass
from ipaddress import IPv4Network
from itertools import chain, islice
from typing import TYPE_CHECKING

from aiodns import DNSResolver

from theHarvester.lib import hostchecker
from theHarvester.lib.cancellation import drain_tasks_after_cancellation
from theHarvester.lib.core import DATA_DIR

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

logger = logging.getLogger(__name__)

#####################################################################
# DNS FORCE
#####################################################################

DNS_NAMES = DATA_DIR / 'wordlists' / 'dns-names.txt'


class DnsForce:
    def __init__(self, domain, dnsserver, verbose: bool = False) -> None:
        self.domain = domain
        self.subdo = False
        self.verbose = verbose
        self.records: dict[str, hostchecker.HostDnsRecords] = {}
        self.completed_count = 0
        self.stop_reason: str | None = None
        self.query_error_count = 0
        self.query_error_types: set[str] = set()
        # self.dnsserver = [dnsserver] if isinstance(dnsserver, str) else dnsserver
        # self.dnsserver = list(map(str, dnsserver.split(','))) if isinstance(dnsserver, str) else dnsserver
        self.dnsserver = dnsserver
        with DNS_NAMES.open('r') as file:
            self.list = file.readlines()
        self.list = [f'{word.strip()}.{self.domain}' for word in self.list]

    async def run(self):
        logger.info(f'Starting DNS brute forcing with {len(self.list)} words')
        checker = hostchecker.Checker(
            self.list,
            nameservers=self.dnsserver,
            concurrency=50,
            request_limit=None,
            runtime_seconds=None,
        )
        resolved_pair, hosts, ips = await checker.check()
        self.records = checker.records
        self.completed_count = getattr(checker, 'completed_count', len(self.list))
        self.stop_reason = getattr(checker, 'stop_reason', None)
        self.query_error_count = getattr(checker, 'query_error_count', 0)
        self.query_error_types = set(getattr(checker, 'query_error_types', set()))
        return resolved_pair, hosts, ips


#####################################################################
# DNS REVERSE
#####################################################################


IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
PORT_REGEX = r'\d{1,5}'
NETMASK_REGEX: str = r'\d{1,2}|' + IP_REGEX
NETWORK_REGEX: str = rf'\b({IP_REGEX})(?:\:({PORT_REGEX}))?(?:\/({NETMASK_REGEX}))?\b'


def serialize_ip_range(ip: str, netmask: str = '24') -> str:
    """Normalize the first IPv4 address in a string as a CIDR range.

    Parameters
    ----------
    ip: str
        Text containing an IPv4 address. Ports and embedded netmasks are ignored.
    netmask: str
        Netmask to apply. The default is ``24``.

    Returns
    -------
    str
        A range such as ``192.168.0.0/24``, or an empty string for invalid input.

    """
    __ip_matches = re.search(NETWORK_REGEX, ip, re.IGNORECASE)
    if __ip_matches and __ip_matches.groups():
        __ip = __ip_matches.group(1)
        __netmask = netmask or __ip_matches.group(3)
        if __ip and __netmask:
            return str(IPv4Network(f'{__ip}/{__netmask}', strict=False))
        elif __ip:
            return str(IPv4Network('{}/{}'.format(__ip, '24'), strict=False))

    # invalid input ip
    return ''


def iter_ips_in_network_range(iprange: str) -> Iterator[str]:
    """Yield usable addresses from a network without materializing the range."""
    try:
        network = IPv4Network(iprange, strict=False)
    except Exception:
        return
    for address in network.hosts():
        yield address.exploded


def list_ips_in_network_range(iprange: str) -> list[str]:
    """Return every usable address in an IPv4 range.

    Parameters
    ----------
    iprange: str
        A range such as ``1.2.3.0/24``. Host bits are ignored.

    Returns
    -------
    list[str]
        Usable addresses in the range.

    """
    return list(iter_ips_in_network_range(iprange))


async def reverse_single_ip(ip: str, resolver: DNSResolver, error_types: set[str] | None = None) -> str:
    """Return the PTR hostname for an IP address, or an empty string.

    Parameters
    ----------
    ip: str
        IP address to resolve.
    resolver: DNSResolver
        Resolver to query.

    Returns
    -------
    str
        The resolved hostname, or an empty string when resolution fails.

    """
    try:
        host = await resolver.gethostbyaddr(ip)
        return host.name if host else ''
    except Exception as error:
        if error_types is not None and not hostchecker.is_expected_dns_absence(error):
            error_types.add(type(error).__name__)
        return ''


@dataclass(frozen=True, slots=True)
class ReverseDNSResult:
    request_count: int
    completed_count: int
    stop_reason: str | None = None


async def reverse_ip_ranges(
    ipranges: tuple[str, ...],
    callback: Callable[[str], None],
    nameservers: list[str] | None = None,
    error_types: set[str] | None = None,
    *,
    concurrency: int = hostchecker.DEFAULT_DNS_CONCURRENCY,
    request_limit: int | None = hostchecker.DEFAULT_DNS_REQUEST_LIMIT,
    runtime_seconds: float | None = hostchecker.DEFAULT_DNS_RUNTIME_SECONDS,
) -> ReverseDNSResult:
    """Reverse unique addresses from all ranges through one bounded job set."""
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency <= 0:
        raise ValueError('reverse DNS concurrency must be a positive integer')
    if request_limit is not None and (
        isinstance(request_limit, bool) or not isinstance(request_limit, int) or request_limit <= 0
    ):
        raise ValueError('reverse DNS request limit must be a positive integer')
    if runtime_seconds is not None and (
        isinstance(runtime_seconds, bool)
        or not isinstance(runtime_seconds, (int, float))
        or not math.isfinite(runtime_seconds)
        or runtime_seconds <= 0
    ):
        raise ValueError('reverse DNS runtime must be a positive finite number')
    seen_addresses: set[str] = set()

    def addresses() -> Iterator[str]:
        for iprange in ipranges:
            for address in iter_ips_in_network_range(iprange):
                if address not in seen_addresses:
                    seen_addresses.add(address)
                    yield address

    remaining_jobs = addresses()
    initial_job_limit = concurrency if request_limit is None else min(concurrency, request_limit + 1)
    initial_jobs = tuple(islice(remaining_jobs, initial_job_limit))
    if not initial_jobs:
        return ReverseDNSResult(0, 0)
    jobs = iter(chain(initial_jobs, remaining_jobs))
    worker_count = min(concurrency, len(initial_jobs), request_limit or concurrency)

    resolver = DNSResolver(loop=asyncio.get_running_loop(), timeout=8, nameservers=nameservers)
    tasks: list[asyncio.Task[None]] = []
    request_count = 0
    completed_count = 0
    stop_reason: str | None = None
    capacity_checked = False
    primary_cancellation: asyncio.CancelledError | None = None

    def next_address() -> str | None:
        nonlocal capacity_checked, request_count, stop_reason
        if request_limit is not None and request_count >= request_limit:
            if not capacity_checked:
                capacity_checked = True
                try:
                    next(jobs)
                except StopIteration:
                    pass
                else:
                    stop_reason = 'query-limit'
            return None
        try:
            address = next(jobs)
        except StopIteration:
            return None
        request_count += 1
        return address

    async def worker() -> None:
        nonlocal completed_count, primary_cancellation
        try:
            while (address := next_address()) is not None:
                log_query(address)
                host = await reverse_single_ip(address, resolver, error_types)
                callback(host)
                log_result(host)
                completed_count += 1
        except asyncio.CancelledError as error:
            if primary_cancellation is None:
                primary_cancellation = error
            current_task = asyncio.current_task()
            for task in tasks:
                if task is not current_task and not task.done():
                    task.cancel()
            raise

    phase_error: BaseException | None = None
    try:
        try:

            async def run_workers() -> None:
                async with asyncio.TaskGroup() as group:
                    for index in range(worker_count):
                        tasks.append(group.create_task(worker(), name=f'reverse-dns:{index}'))
                if primary_cancellation is not None:
                    raise primary_cancellation

            if runtime_seconds is None:
                await run_workers()
            else:
                async with asyncio.timeout(runtime_seconds):
                    await run_workers()
        except TimeoutError:
            stop_reason = 'runtime-limit'
    except BaseException as error:
        phase_error = error

    cleanup_interruptions: tuple[asyncio.CancelledError, ...] = ()
    close_error: BaseException | None = None
    if close := getattr(resolver, 'close', None):
        close_task = asyncio.create_task(close(), name='reverse-dns-resolver-close')
        cleanup_interruptions = await drain_tasks_after_cancellation((close_task,), cancel=False)
        close_error = (
            asyncio.CancelledError('reverse DNS resolver close cancelled') if close_task.cancelled() else close_task.exception()
        )
    if isinstance(phase_error, asyncio.CancelledError):
        raise phase_error
    if cleanup_interruptions:
        raise cleanup_interruptions[0]
    if phase_error is not None:
        raise phase_error
    if close_error is not None:
        raise close_error
    return ReverseDNSResult(request_count, completed_count, stop_reason)


async def reverse_all_ips_in_range(
    iprange: str,
    callback: Callable,
    nameservers: list[str] | None = None,
    error_types: set[str] | None = None,
) -> None:
    """Resolve usable addresses from one range with the shared bounds.

    Parameters
    ----------
    iprange: str
        An IPv4 range formatted as ``x.x.x.x/y``. Host bits are ignored.
    callback: Callable
        Function called for each resolved hostname.
    nameservers: list[str] | None
        DNS servers to query.
    error_types: set[str] | None
        Sink for unexpected resolver or transport error names.

    """
    await reverse_ip_ranges((iprange,), callback, nameservers, error_types)


#####################################################################
# IO
#####################################################################


def log_query(ip: str) -> None:
    """Display the IP address currently being queried."""
    sys.stdout.write(chr(27) + '[2K' + chr(27) + '[G')
    sys.stdout.write('\r' + ip + ' - ')
    sys.stdout.flush()


def log_result(host: str) -> None:
    """Log a hostname returned by reverse DNS."""
    if host:
        logger.info(host)


def generate_postprocessing_callback(target: str, **allhosts: list[str]) -> Callable:
    """Return a callback that appends matching PTR hostnames to each collection."""

    def append_matching_hosts(host: str) -> None:
        if host and target in host:
            for __name, __hosts in allhosts.items():
                if host not in __hosts:
                    __hosts.append(host)

    return append_matching_hosts
