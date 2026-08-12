import argparse
import asyncio
import hashlib
import inspect
import json
import logging
import os
import re
import secrets
import string
import sys
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import anyio
import netaddr
import ujson
from aiomultiprocess import Pool

from theHarvester.discovery import (
    api_endpoints,
    apisguru,
    arquivo,
    baidusearch,
    bevigil,
    bravesearch,
    bufferoverun,
    builtwith,
    censysearch,
    certspottersearch,
    chaos,
    commoncrawl,
    criminalip,
    crtname,
    crtsh,
    dnsdb,
    dnssearch,
    duckduckgosearch,
    dymosearch,
    fofa,
    fullhuntsearch,
    githubcode,
    gitlabsearch,
    hackertarget,
    haveibeenpwned,
    hibpverified,
    hudsonrocksearch,
    huntersearch,
    intelxsearch,
    leakix,
    leaklookup,
    mojeek,
    netlas,
    onyphe,
    otxsearch,
    pentesttools,
    projectdiscovery,
    rapiddns,
    robtex,
    rocketreach,
    search_dehashed,
    search_dnsdumpster,
    searchhunterhow,
    securityscorecard,
    securitytrailssearch,
    sherlockeye,
    shodan_internetdb,
    shodanct,
    shodansearch,
    sourcegraph,
    subdomaincenter,
    subdomainfinderc99,
    takeover,
    thc,
    tombasearch,
    urlscan,
    virustotal,
    waybackarchive,
    whoisxml,
    windvane,
    yahoosearch,
    zoomeyesearch,
)
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib import hostchecker
from theHarvester.lib.active_evidence import ActionExecution, ActiveEvidence, ArtifactReference
from theHarvester.lib.completed_result import (
    EXECUTION_STATUSES,
    CompletedResult,
    ExecutionStatus,
    ResultKind,
    ResultObservation,
    SourceExecution,
)
from theHarvester.lib.core import DATA_DIR, Core, show_default_error_message
from theHarvester.lib.database import ResultStore
from theHarvester.lib.dns_consensus import AioDNSResolverVantage
from theHarvester.lib.enumeration import (
    DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
    DEFAULT_RESULT_LIMIT,
    DEFAULT_RESULT_START,
    EnumerationOptions,
)
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.output import configure_logging, output_logger, print_linkedin_people, print_section, sorted_unique
from theHarvester.lib.recursive_dns import (
    DEFAULT_RECURSIVE_DNS_QUERY_LIMIT,
    RecursiveDNSLimits,
    discover_recursive_dns,
)
from theHarvester.lib.resolver_selection import DEFAULT_DNS_RESOLVERS, normalize_resolver_addresses
from theHarvester.lib.source_catalog import (
    SOURCE_SPECS,
    ActivityClass,
    ResultRoute,
    SourceSpec,
    get_source_spec,
)
from theHarvester.lib.virtual_host import (
    DEFAULT_VHOST_CONCURRENCY,
    DEFAULT_VHOST_REQUEST_LIMIT,
    DEFAULT_VHOST_RUNTIME_SECONDS,
    DEFAULT_VHOST_TIMEOUT_SECONDS,
    VirtualHostDiscoveryCancelled,
    VirtualHostLimits,
    VirtualHostObservation,
    discover_harvested_virtual_hosts,
    normalize_virtual_host_candidates,
    normalize_virtual_host_endpoint,
    normalize_virtual_host_hostname,
)
from theHarvester.screenshot.screenshot import ScreenShotter

logger = logging.getLogger(__name__)


def _normalize_hosts_for_storage(discovered_hosts: Iterable[object], target: str) -> set[str]:
    normalized_target = target.strip().lower().removeprefix('www.').rstrip('.')
    return {
        normalized
        for host in discovered_hosts
        if (normalized := normalize_scoped_hostname(host, normalized_target)) and normalized != normalized_target
    }


def _normalize_ip_addresses(values: Iterable[object]) -> set[str]:
    addresses: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            addresses.add(str(ip_address(value.strip())))
        except ValueError:
            continue
    return addresses


def sanitize_for_xml(text: str) -> str:
    """Sanitize text for safe inclusion in XML documents."""
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&apos;')
    return text


def sanitize_filename(filename: str) -> str:
    filename = os.path.basename(filename)
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    # Remove consecutive underscores
    filename = re.sub(r'_+', '_', filename)
    filename = filename.strip('_.')
    if filename.startswith('.'):
        filename = '_' + filename
    # Ensure we have a valid filename
    if not filename:
        filename = 'sanitized_file'
    return filename


async def start(
    rest_args: argparse.Namespace | EnumerationOptions | None = None,
    *,
    completed_result_checkpoint: Callable[[CompletedResult], Awaitable[None]] | None = None,
    persist_completed_result: bool = False,
    include_breaches: bool = False,
    return_completed_result: bool = False,
    return_dns_brute_result: bool = False,
    result_database: str | Path | None = None,
    completed_run_id: UUID | None = None,
):
    """Main program function"""
    parser = argparse.ArgumentParser(
        description='theHarvester is used to gather open source intelligence (OSINT) on a company or domain.'
    )
    parser.add_argument('-d', '--domain', help='Company name or domain to search.', required=True)
    parser.add_argument(
        '-l',
        '--limit',
        help='Maximum results requested from each source that supports result limits (default: 500).',
        default=DEFAULT_RESULT_LIMIT,
        type=int,
    )
    parser.add_argument(
        '-S',
        '--start',
        help='Result offset for sources that support pagination (default: 0).',
        default=DEFAULT_RESULT_START,
        type=int,
    )
    parser.add_argument(
        '-p',
        '--proxies',
        help='Use proxies.yaml for supported discovery-source and takeover requests.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-s',
        '--shodan',
        help='Use Shodan to query discovered hosts.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '--screenshot',
        help='Save screenshots of reachable discovered hosts to DIR. This sends direct browser requests.',
        metavar='DIR',
        default='',
        type=str,
    )

    parser.add_argument(
        '-e',
        '--dns-server',
        help='Accepted for compatibility but currently unused; use --dns-resolvers to select resolvers.',
    )
    parser.add_argument(
        '-t',
        '--take-over',
        help='Check discovered hosts for known takeover indicators, using configured proxies when enabled.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-r',
        '--dns-resolve',
        help=(
            'Resolve discovered hostnames. Pass comma-separated resolver IPs or a text file with one IP per line; '
            'omit the value to use defaults.'
        ),
        default='',
        type=str,
        nargs='?',
    )
    parser.add_argument(
        '--dns-resolvers',
        dest='dns_resolver_input',
        help=(
            'Select resolver IPs for DNS actions without enabling hostname resolution. '
            'Pass comma-separated IPs or a text file with one IP per line.'
        ),
        default='',
        metavar='IPS_OR_FILE',
    )
    parser.add_argument(
        '-n',
        '--dns-lookup',
        help=(
            'Perform PTR lookups across the /24 network containing each discovered IPv4 address. This sends active DNS queries.'
        ),
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-c',
        '--dns-brute',
        help='Perform a DNS brute force on the domain.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '--dns-recursive-depth',
        help='Enable recursive DNS discovery to this maximum depth. Zero disables it.',
        default=0,
        type=int,
    )
    parser.add_argument(
        '--dns-recursive-query-limit',
        help='Hard cap on recursive DNS record queries across all resolver vantages.',
        default=DEFAULT_RECURSIVE_DNS_QUERY_LIMIT,
        type=int,
    )
    parser.add_argument(
        '--dns-recursive-runtime-seconds',
        help='Hard runtime cap in seconds for recursive DNS discovery.',
        default=DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
        type=float,
    )
    parser.add_argument(
        '-f',
        '--filename',
        help='Write NAME.json, NAME.xml, and NAME.jsonl.',
        metavar='NAME',
        default='',
        type=str,
    )
    parser.add_argument('-w', '--wordlist', help='Path to the endpoint wordlist used by --api-scan.', default='')
    parser.add_argument(
        '-a',
        '--api-scan',
        help='Check common API paths with GET, HEAD, and OPTIONS. Requests follow redirects.',
        action='store_true',
    )
    vhost_group = parser.add_argument_group(
        'virtual host discovery',
        'P2 direct interaction (active reconnaissance): sends direct HTTP and TLS requests. '
        'For normal use, pass only --vhost; bounded safety defaults apply automatically. '
        'Supplying --vhost-endpoint or --vhost-candidate also enables discovery.',
    )
    vhost_group.add_argument(
        '--vhost',
        help='Test harvested in-scope hostnames against harvested literal IPs, using HTTPS before HTTP.',
        action='store_true',
    )
    vhost_group.add_argument(
        '--vhost-endpoint',
        help='Replace harvested IPs with one authorized HTTP or HTTPS endpoint using a literal IP.',
        default='',
    )
    vhost_group.add_argument(
        '--vhost-candidate',
        dest='vhost_candidates',
        help='Repeat to add an authorized in-scope hostname. Candidate names are never resolved through DNS.',
        action='append',
        default=[],
        metavar='HOSTNAME',
    )
    vhost_advanced_group = parser.add_argument_group(
        'virtual host advanced controls',
        'Optional safety overrides. Bounded defaults apply when these options are omitted.',
    )
    vhost_advanced_group.add_argument(
        '--vhost-request-limit',
        help='Hard request cap shared by baseline, controls, candidates, and confirmations (default: %(default)s).',
        default=DEFAULT_VHOST_REQUEST_LIMIT,
        type=int,
    )
    vhost_advanced_group.add_argument(
        '--vhost-runtime-seconds',
        help='Hard wall-clock cap for virtual-host discovery (default: %(default)s seconds).',
        default=DEFAULT_VHOST_RUNTIME_SECONDS,
        type=float,
    )
    vhost_advanced_group.add_argument(
        '--vhost-timeout-seconds',
        help='Timeout for each virtual-host request (default: %(default)s seconds).',
        default=DEFAULT_VHOST_TIMEOUT_SECONDS,
        type=float,
    )
    vhost_advanced_group.add_argument(
        '--vhost-concurrency',
        help='Maximum concurrent candidate requests (default: %(default)s).',
        default=DEFAULT_VHOST_CONCURRENCY,
        type=int,
    )
    vhost_advanced_group.add_argument(
        '--vhost-insecure',
        help='Do not verify TLS certificates for HTTPS probes; evidence records tls_verified=false.',
        action='store_true',
    )
    parser.add_argument(
        '-q',
        '--quiet',
        help='Suppress missing API key warnings and reading the api-keys file.',
        default=False,
        action='store_true',
    )
    parser.add_argument('-v', '--verbose', help='Show informational diagnostic messages.', action='store_true')
    parser.add_argument(
        '-b',
        '--source',
        help=(
            'Comma-separated source names or source capabilities. Multiple capabilities select the union of matching '
            'sources; they do not filter returned fields. Capabilities: '
            f'subdomains, emails, ips, asns, urls, people, breaches, all. Sources: '
            f'{", ".join(sorted(SOURCE_SPECS, key=str.casefold))}'
        ),
    )

    # determines if the filename is coming from rest api or user
    rest_filename = ''
    dnsbrute: tuple[bool, bool]
    # indicates this from the rest API
    if rest_args:
        if rest_args.source and rest_args.source == 'getsources':
            return list(sorted(Core.get_supportedengines()))
        args = EnumerationOptions.from_namespace(rest_args)
        filename = args.filename
        if args.dns_brute:
            dnsbrute = (args.dns_brute, return_dns_brute_result)
        else:
            dnsbrute = (args.dns_brute, False)
            # We need to make sure the filename is random as to not overwrite other files
            alphabet = string.ascii_letters + string.digits
            rest_filename += f'{"".join(secrets.choice(alphabet) for _ in range(32))}_{filename}' if len(filename) != 0 else ''
    else:
        args = EnumerationOptions.from_namespace(parser.parse_args())
        filename = args.filename
        dnsbrute = (args.dns_brute, False)
        configure_logging(verbose=args.verbose)
        if args.verbose:
            logger.info('Verbose logging enabled')
    vhost_enabled = args.vhost or bool(args.vhost_endpoint) or bool(args.vhost_candidates)
    vhost_scope = ''
    vhost_endpoint = ''
    vhost_candidates: tuple[str, ...] = ()
    vhost_limits: VirtualHostLimits | None = None
    if vhost_enabled:
        vhost_scope = normalize_virtual_host_hostname(args.domain)
        if args.proxies:
            raise ValueError('virtual-host discovery supports direct transport only; do not use --proxies')
        vhost_endpoint = normalize_virtual_host_endpoint(args.vhost_endpoint) if args.vhost_endpoint else ''
        vhost_candidates = normalize_virtual_host_candidates(vhost_scope, args.vhost_candidates)
        vhost_limits = VirtualHostLimits(
            request_limit=args.vhost_request_limit,
            runtime_seconds=args.vhost_runtime_seconds,
            timeout_seconds=args.vhost_timeout_seconds,
            concurrency=args.vhost_concurrency,
        )
    Core.quiet = getattr(args, 'quiet', False)
    try:
        db = ResultStore() if result_database is None else ResultStore(result_database)
        await db.initialize()
    except (AttributeError, OSError, RuntimeError, ValueError) as init_error:
        if not args.quiet:
            output_logger.info(f'Error initializing result store: {init_error}')
        raise ValueError('Failed to initialize result store')

    if len(filename) > 0:
        if filename.startswith('~/'):
            # Allow home directory expansion but sanitize the rest
            base_path = await anyio.Path('~').expanduser()
            sanitized = sanitize_filename(filename[2:])
            filename = str(base_path.joinpath(sanitized))
        elif os.path.isabs(filename):
            # For absolute paths, sanitize just the filename component
            dirname = os.path.dirname(filename)
            basename = sanitize_filename(os.path.basename(filename))
            filename = os.path.join(dirname, basename)
        else:
            # For relative paths, sanitize the entire filename
            filename = sanitize_filename(filename)
    run_started_at = datetime.now(UTC)
    run_id = completed_run_id or uuid4()

    all_emails: list = []
    all_hosts: list = []
    all_ip: list = []
    all_people: list[dict[str, str]] = []
    all_infostealers: list[dict[str, object]] = []
    dnslookup = args.dns_lookup
    dnsserver = args.dns_server  # TODO arg is not used anywhere replace with resolvers wordlist arg dnsresolve
    dnsresolve: str | None = args.dns_resolve
    final_dns_resolver_list = normalize_resolver_addresses(args.dns_resolvers) if args.dns_resolvers else []
    if args.dns_resolver_input and dnsresolve not in {'', None}:
        raise ValueError('Pass resolver values through either --dns-resolvers or --dns-resolve, not both')
    resolver_input = args.dns_resolver_input or (dnsresolve if dnsresolve is not None else '')
    if resolver_input:
        resolver_candidates: list[str] = []
        if await anyio.Path(resolver_input).exists():
            async with await anyio.open_file(resolver_input, encoding='UTF-8') as fp:
                async for line in fp:
                    resolver_candidates.append(line)
        else:
            resolver_candidates.extend(resolver_input.split(','))
        final_dns_resolver_list = normalize_resolver_addresses(resolver_candidates)
    elif dnsresolve is None and not final_dns_resolver_list:
        final_dns_resolver_list = list(DEFAULT_DNS_RESOLVERS)

    recursive_depth = getattr(args, 'dns_recursive_depth', 0)
    recursive_limits = None
    if recursive_depth < 0:
        raise ValueError('--dns-recursive-depth cannot be negative')
    if recursive_depth > 0:
        if len(final_dns_resolver_list) != 3:
            raise ValueError('--dns-recursive-depth requires exactly three resolver addresses')
        recursive_limits = RecursiveDNSLimits(
            depth=recursive_depth,
            query_limit=getattr(args, 'dns_recursive_query_limit', DEFAULT_RECURSIVE_DNS_QUERY_LIMIT),
            runtime_seconds=getattr(args, 'dns_recursive_runtime_seconds', 60.0),
        )

    engines: list = []
    # If the user specifies
    full: list = []
    resolved_screenshot_hosts: set[str] = set()
    reported_host_ip_pairs: set[tuple[str, str]] = set()
    ips: list = []
    host_ip: list = []
    limit: int = args.limit
    shodan = args.shodan
    start: int = args.start
    all_urls: list = []
    vhost_observations: list[VirtualHostObservation] = []
    word: str = args.domain.rstrip('\n')
    takeover_status = args.take_over
    use_proxy = args.proxies
    linkedin_people_list_tracker: list = []
    twitter_people_list_tracker: list = []
    total_asns: list = []
    all_breaches: list[str] = []
    all_frameworks: list[str] = []
    all_languages: list[str] = []
    all_servers: list[str] = []
    all_cms: list[str] = []
    all_analytics: list[str] = []
    endpoints_found: set[str] = set()
    screenshot_artifacts: list[ArtifactReference] = []
    screenshot_hostnames: set[str] = set()
    screenshot_ip_addresses: set[str] = set()
    shodan_evidence: list[str] = []
    takeover_results: dict[str, list[dict[str, str]]] = {}
    linkedin_people_list_tracker = []
    twitter_people_list_tracker = []
    total_asns = []
    source_executions: list[SourceExecution] = []
    observations: set[ResultObservation] = set()
    action_executions: list[ActionExecution] = []
    dns_resolution_duration_ms = 0.0
    dns_resolution_ips: set[str] = set()
    dns_resolution_completed_count = 0
    dns_resolution_query_error_count = 0
    dns_resolution_error_types: set[str] = set()
    dns_resolution_failure_types: set[str] = set()
    dns_resolution_cancelled = False

    def record_missing_credentials(source: str) -> None:
        source_executions.append(SourceExecution(source, 'skipped', 0, 0, 'MissingKeyError', 'missing-credentials'))

    def confirmed_virtual_hostnames() -> list[str]:
        return sorted({observation.hostname for observation in vhost_observations})

    def finish_completed_result(
        *,
        extra_hostnames: Iterable[str] = (),
        committed_sources_only: bool = False,
    ) -> CompletedResult | None:
        groups: dict[ResultKind, Iterable[str]] = {
            'analytics': map(str, all_analytics),
            'asn': map(str, total_asns),
            'breach': map(str, all_breaches),
            'cms': map(str, all_cms),
            'email': map(str, all_emails),
            'framework': map(str, all_frameworks),
            'hostname': (
                _normalize_hosts_for_storage(all_hosts, word) | screenshot_hostnames | set(confirmed_virtual_hostnames())
            ),
            'infostealer': (
                json.dumps(stealer, ensure_ascii=False, separators=(',', ':'), sort_keys=True) for stealer in all_infostealers
            ),
            'ip': _normalize_ip_addresses(all_ip) | screenshot_ip_addresses,
            'language': map(str, all_languages),
            'linkedin-person': map(str, linkedin_people_list_tracker),
            'person': (json.dumps(person, ensure_ascii=False, separators=(',', ':'), sort_keys=True) for person in all_people),
            'server': map(str, all_servers),
            'twitter-person': map(str, twitter_people_list_tracker),
            'url': map(str, all_urls),
        }
        if committed_sources_only:
            committed_groups: dict[ResultKind, list[str]] = {}
            for observation in observations:
                committed_groups.setdefault(observation.kind, []).append(observation.value)
            groups = {kind: iter(values) for kind, values in committed_groups.items()}
        elif extra_hostnames:
            groups['hostname'] = (
                _normalize_hosts_for_storage((*all_hosts, *extra_hostnames), word)
                | screenshot_hostnames
                | set(confirmed_virtual_hostnames())
            )
        try:
            return CompletedResult.finish(
                run_id=run_id,
                target=word,
                started_at=run_started_at,
                completed_at=datetime.now(UTC),
                groups=groups,
                source_executions=source_executions,
                observations=observations,
                active_evidence=ActiveEvidence(tuple(action_executions)),
                virtual_hosts=vhost_observations,
            )
        except (ValueError, TypeError) as error:
            output_logger.info(f'[!] An error occurred while completing the result: {error}')
            return None

    async def checkpoint_completed_result(
        *,
        extra_hostnames: Iterable[str] = (),
        committed_sources_only: bool = False,
    ) -> None:
        if (
            completed_result_checkpoint is not None
            and (
                result := finish_completed_result(
                    extra_hostnames=extra_hostnames,
                    committed_sources_only=committed_sources_only,
                )
            )
            is not None
        ):
            await completed_result_checkpoint(result)

    async def persist_result(completed_result: CompletedResult | None) -> None:
        if completed_result is None:
            return
        try:
            await db.save_run(completed_result)
        except Exception as error:
            output_logger.info(f'[!] An error occurred while storing the completed result: {error}')

    async def checkpoint_action_result(
        *,
        extra_hostnames: Iterable[str] = (),
    ) -> None:
        result = finish_completed_result(extra_hostnames=extra_hostnames)
        if result is None:
            return
        try:
            if completed_result_checkpoint is not None:
                await completed_result_checkpoint(result)
        except asyncio.CancelledError:
            await persist_result(result)
            raise

    def record_dns_resolution_execution(*, handler_cancelled: bool = False) -> None:
        if dnsresolve == '':
            return
        if dnsresolve is not None and not final_dns_resolver_list:
            action_executions.append(
                ActionExecution.finish(
                    action='dns-resolve',
                    status='skipped',
                    duration_ms=0,
                    groups={},
                    stop_reason='no-valid-resolvers',
                )
            )
            return
        if handler_cancelled and not (
            dns_resolution_cancelled
            or dns_resolution_completed_count
            or dns_resolution_failure_types
            or dns_resolution_query_error_count
        ):
            return

        status: ExecutionStatus
        error_type: str | None = None
        stop_reason: str | None = None
        if dns_resolution_cancelled:
            status = 'partial' if dns_resolution_completed_count else 'failed'
            error_type = 'CancelledError'
            stop_reason = 'cancelled'
        elif dns_resolution_failure_types:
            status = 'partial' if dns_resolution_completed_count else 'failed'
            error_type = next(iter(sorted(dns_resolution_failure_types)))
        elif dns_resolution_completed_count:
            status = 'partial' if dns_resolution_query_error_count else 'completed'
            error_type = next(iter(sorted(dns_resolution_error_types)), None)
            stop_reason = 'query-errors' if dns_resolution_query_error_count else None
        elif not handler_cancelled:
            status = 'skipped'
            stop_reason = 'no-input'
        else:
            return
        action_executions.append(
            ActionExecution.finish(
                action='dns-resolve',
                status=status,
                duration_ms=dns_resolution_duration_ms,
                groups={'ip': dns_resolution_ips},
                error_type=error_type,
                stop_reason=stop_reason,
            )
        )

    async def collect_and_store(
        search_engine: Any,
        source_spec: SourceSpec,
        source_observations: set[ResultObservation],
    ) -> None:
        """Process a source and persist its declared consolidated result routes.

        :param search_engine: search engine to fetch details from
        :param source_spec: canonical source identity and declared result routes
        """
        nonlocal dns_resolution_cancelled, dns_resolution_completed_count
        nonlocal dns_resolution_duration_ms, dns_resolution_query_error_count

        source = source_spec.name
        routes = source_spec.routes
        if source:
            output_logger.info(f'[*] Searching {source[0].upper() + source[1:]}. ')
        await search_engine.process(use_proxy)

        def record_source_observations(source_name: str, kind: ResultKind, values: Iterable[object]) -> None:
            source_observations.update(
                ResultObservation(source_name, kind, value) for item in values if (value := str(item).strip())
            )

        if ResultRoute.SUBDOMAINS in routes:
            discovered_hosts = await search_engine.get_hostnames()
            host_names = list(_normalize_hosts_for_storage(discovered_hosts, word))
            paired_hosts: set[str] = set()
            if source == 'rapiddns':
                for host, address in await search_engine.get_host_ip_pairs():
                    normalized = normalize_scoped_hostname(host, word)
                    if normalized and normalized in host_names:
                        paired_hosts.add(normalized)
                        reported_host_ip_pairs.add((normalized, address))

            if source != 'hackertarget' and source != 'pentesttools':
                # If a source is inside this conditional, it means the hosts returned must be resolved to obtain ip
                # This should only be checked if --dns-resolve has a wordlist
                hosts_to_resolve = [host for host in host_names if host not in paired_hosts]
                if dnsresolve != '' and hosts_to_resolve:
                    # indicates that -r was passed in if dnsresolve is None
                    dns_resolution_started = time.perf_counter()
                    try:
                        full_hosts_checker = hostchecker.Checker(hosts_to_resolve, final_dns_resolver_list)
                        # If full, this is only getting resolved hosts
                        (
                            resolved_pair,
                            resolved_hosts,
                            temp_ips,
                        ) = await full_hosts_checker.check()
                    except asyncio.CancelledError:
                        dns_resolution_duration_ms += (time.perf_counter() - dns_resolution_started) * 1000
                        dns_resolution_cancelled = True
                        raise
                    except Exception as error:
                        dns_resolution_duration_ms += (time.perf_counter() - dns_resolution_started) * 1000
                        dns_resolution_failure_types.add(type(error).__name__)
                        raise
                    dns_resolution_duration_ms += (time.perf_counter() - dns_resolution_started) * 1000
                    dns_resolution_completed_count += 1
                    dns_resolution_query_error_count += getattr(full_hosts_checker, 'query_error_count', 0)
                    dns_resolution_error_types.update(getattr(full_hosts_checker, 'query_error_types', set()))
                    dns_resolution_ips.update(_normalize_ip_addresses(temp_ips))
                    all_ip.extend(temp_ips)
                    full.extend(resolved_pair)
                    if source == 'rapiddns':
                        full.extend(host for host in host_names if host not in resolved_hosts)
                    resolved_screenshot_hosts.update(resolved_hosts)
                else:
                    full.extend(host_names)
            else:
                full.extend(host_names)
            all_hosts.extend(host_names)
            record_source_observations(source, 'hostname', host_names)

        if ResultRoute.EMAILS in routes:
            email_list = await search_engine.get_emails()
            all_emails.extend(email_list)
            record_source_observations(source, 'email', email_list)

        if ResultRoute.IPS in routes:
            ips_list = await search_engine.get_ips()
            all_ip.extend(ips_list)
            record_source_observations(source, 'ip', _normalize_ip_addresses(ips_list))

        if ResultRoute.PEOPLE in routes:
            people_list = await search_engine.get_people()
            all_people.extend(people_list)
            people_evidence = (
                json.dumps(person, ensure_ascii=False, separators=(',', ':'), sort_keys=True) for person in people_list
            )
            record_source_observations(source, 'person', people_evidence)

        if ResultRoute.URLS in routes:
            urls = await search_engine.get_urls()
            all_urls.extend(urls)
            record_source_observations(source, 'url', urls)

        if ResultRoute.ASNS in routes:
            fasns = await search_engine.get_asns()
            total_asns.extend(fasns)
            record_source_observations(source, 'asn', fasns)

        if ResultRoute.BREACHES in routes:
            breach_names = await search_engine.get_breach_names()
            all_breaches.extend(breach_names)
            record_source_observations(source, 'breach', breach_names)
        if source == 'builtwith':
            technology_results: tuple[tuple[str, list[Any], ResultKind], ...] = (
                ('get_frameworks', all_frameworks, 'framework'),
                ('get_languages', all_languages, 'language'),
                ('get_servers', all_servers, 'server'),
                ('get_cms', all_cms, 'cms'),
                ('get_analytics', all_analytics, 'analytics'),
            )
            for getter_name, results, result_type in technology_results:
                values = await getattr(search_engine, getter_name)()
                results.extend(values)
                record_source_observations(source, result_type, values)
        if source == 'hudsonrock':
            infostealers = await search_engine.get_infostealers()
            all_infostealers.extend(infostealers)
            record_source_observations(
                source,
                'infostealer',
                (json.dumps(stealer, ensure_ascii=False, separators=(',', ':'), sort_keys=True) for stealer in infostealers),
            )

    async def store(search_engine: Any, source: str) -> None:
        source_spec = get_source_spec(source)
        source_name = source_spec.name
        source_observations: set[ResultObservation] = set()
        logger.info(f'Source {source_name} started')
        started = time.perf_counter()
        try:
            await collect_and_store(search_engine, source_spec, source_observations)
            reported_status = getattr(search_engine, 'execution_status', None)
            if reported_status is None:
                execution_status: ExecutionStatus = 'completed'
            elif isinstance(reported_status, str) and reported_status in EXECUTION_STATUSES:
                execution_status = cast('ExecutionStatus', reported_status)
            else:
                raise ValueError(f'Source {source_name} reported invalid execution status: {reported_status!r}')
        except asyncio.CancelledError:
            result_count = len(source_observations)
            source_executions.append(
                SourceExecution(
                    source_name,
                    'partial' if result_count else 'failed',
                    (time.perf_counter() - started) * 1000,
                    result_count,
                    'CancelledError',
                    'cancelled',
                )
            )
            observations.update(source_observations)
            raise
        except Exception as error:
            result_count = len(source_observations)
            duration_ms = (time.perf_counter() - started) * 1000
            logger.exception(f'Source {source_name} failed after {duration_ms / 1000:.2f}s with {result_count} result(s)')
            source_executions.append(
                SourceExecution(
                    source_name,
                    'partial' if result_count else 'failed',
                    duration_ms,
                    result_count,
                    type(error).__name__,
                )
            )
            observations.update(source_observations)
            await checkpoint_completed_result(committed_sources_only=True)
            raise
        result_count = len(source_observations)
        duration_ms = (time.perf_counter() - started) * 1000
        stop_reason = getattr(search_engine, 'stop_reason', None)
        source_executions.append(
            SourceExecution(
                source_name,
                execution_status,
                duration_ms,
                result_count,
                stop_reason=stop_reason if isinstance(stop_reason, str) else None,
            )
        )
        observations.update(source_observations)
        await checkpoint_completed_result(committed_sources_only=True)
        stop_summary = f'; stop={stop_reason}' if isinstance(stop_reason, str) else ''
        logger.info(
            f'Source {source_name} finished in {duration_ms / 1000:.2f}s: '
            f'status={execution_status}; results={result_count}{stop_summary}'
        )

    stor_lst = []
    if args.source is not None:
        engines = Core.expand_source_selection(args.source)
    activities = {get_source_spec(engine).activity for engine in engines if engine in SOURCE_SPECS}
    if shodan:
        activities.add(ActivityClass.PASSIVE)
    if dnslookup or dnsbrute[0] or dnsresolve != '' or recursive_limits is not None:
        activities.add(ActivityClass.DNS)
    if takeover_status or args.screenshot or args.api_scan or vhost_enabled:
        activities.add(ActivityClass.DIRECT)
    if activities:
        activity_labels = {
            ActivityClass.PASSIVE: 'P0 passive collection',
            ActivityClass.DNS: 'P1 DNS interaction',
            ActivityClass.DIRECT: 'P2 direct interaction',
        }
        output_logger.info(f'[*] Activity: {", ".join(activity_labels[item] for item in ActivityClass if item in activities)}')

    if args.source is not None:
        # Iterate through search engines in order
        if set(engines).issubset(Core.get_supportedengines()):
            output_logger.info(f'\n[*] Target: {word} \n')

            for engineitem in engines:
                if engineitem == 'apis-guru':
                    try:
                        apis_guru_search = apisguru.SearchApisGuru(word, limit)
                        stor_lst.append(store(apis_guru_search, engineitem))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'arquivo':
                    try:
                        arquivo_search = arquivo.SearchArquivo(word, limit)
                        stor_lst.append(store(arquivo_search, engineitem))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'baidu':
                    try:
                        baidu_search = baidusearch.SearchBaidu(word, limit)
                        stor_lst.append(
                            store(
                                baidu_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'bevigil':
                    try:
                        bevigil_search = bevigil.SearchBeVigil(word)
                        stor_lst.append(
                            store(
                                bevigil_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                        show_default_error_message(engineitem, word, error=e)

                elif engineitem == 'brave':
                    try:
                        brave_search = bravesearch.SearchBrave(word, limit)
                        stor_lst.append(
                            store(
                                brave_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                        show_default_error_message(engineitem, word, error=e)

                elif engineitem == 'bufferoverun':
                    try:
                        bufferoverun_search = bufferoverun.SearchBufferover(word)
                        stor_lst.append(
                            store(
                                bufferoverun_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'builtwith':
                    try:
                        builtwith_search = builtwith.SearchBuiltWith(word)
                        stor_lst.append(store(builtwith_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            output_logger.info(f"Failed to perform BuiltWith search for word: '{word}'")
                            output_logger.info(f'A Missing Key Error occurred in builtwith: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'censys':
                    try:
                        censys_search = censysearch.SearchCensys(word, limit)
                        stor_lst.append(
                            store(
                                censys_search,
                                engineitem,
                            )
                        )
                    except MissingKey as mk:
                        record_missing_credentials(engineitem)
                        if not args.quiet:
                            output_logger.info(f'Censys API key is missing or invalid: {mk}')
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network error while querying Censys: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Timeout occurred while contacting Censys: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Censys returned unexpected data: {ve}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Censys module: {e}')

                elif engineitem == 'certspotter':
                    try:
                        certspotter_search = certspottersearch.SearchCertspoter(word)
                        stor_lst.append(store(certspotter_search, engineitem))
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Certspotter: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Certspotter timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Certspotter returned invalid data: {ve}')
                    except MissingKey as mk:
                        record_missing_credentials(engineitem)
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from Certspotter (missing key): {mk}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Certspotter module: {e}')

                elif engineitem == 'chaos':
                    try:
                        chaos_search = chaos.SearchChaos(word)
                        stor_lst.append(
                            store(
                                chaos_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Chaos: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'commoncrawl':
                    try:
                        commoncrawl_search = commoncrawl.SearchCommoncrawl(word, limit)
                        stor_lst.append(
                            store(
                                commoncrawl_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'criminalip':
                    try:
                        criminalip_search = criminalip.SearchCriminalIP(word)
                        stor_lst.append(
                            store(
                                criminalip_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing key error occurred in criminalip: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'crt-name':
                    try:
                        crt_name_search = crtname.SearchCrtName(word)
                        stor_lst.append(store(crt_name_search, engineitem))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'crtsh':
                    try:
                        crtsh_search = crtsh.SearchCrtsh(word)
                        stor_lst.append(store(crtsh_search, 'CRTsh'))
                    except Exception as e:
                        output_logger.info(f'[!] A timeout occurred with crtsh, cannot find {args.domain}\n {e}')

                elif engineitem == 'dehashed':
                    try:
                        dehashed_search = search_dehashed.SearchDehashed(word, limit=limit)
                        stor_lst.append(
                            store(
                                dehashed_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in dehashed: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'dnsdb':
                    try:
                        dnsdb_search = dnsdb.SearchDNSDB(word)
                        stor_lst.append(store(dnsdb_search, engineitem))
                    except MissingKey as e:
                        record_missing_credentials(engineitem)
                        if not args.quiet:
                            output_logger.info(e)
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'dnsdumpster':
                    try:
                        dnsdumpster_search = search_dnsdumpster.SearchDNSDumpster(word)
                        stor_lst.append(
                            store(
                                dnsdumpster_search,
                                engineitem,
                            )
                        )
                    except MissingKey as e:
                        record_missing_credentials(engineitem)
                        if not args.quiet:
                            output_logger.info(e)
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'duckduckgo':
                    duckduckgo_search = duckduckgosearch.SearchDuckDuckGo(word, limit)
                    stor_lst.append(
                        store(
                            duckduckgo_search,
                            engineitem,
                        )
                    )

                elif engineitem == 'dymo':
                    try:
                        dymo_search = dymosearch.SearchDymo(word)
                        stor_lst.append(store(dymo_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in dymo: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'fofa':
                    try:
                        fofa_search = fofa.SearchFofa(word)
                        stor_lst.append(
                            store(
                                fofa_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Fofa: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'fullhunt':
                    try:
                        fullhunt_search = fullhuntsearch.SearchFullHunt(word)
                        stor_lst.append(store(fullhunt_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in fullhunt: {e}')

                elif engineitem == 'github-code':
                    try:
                        github_search = githubcode.SearchGithubCode(word, limit)
                        stor_lst.append(
                            store(
                                github_search,
                                engineitem,
                            )
                        )
                    except MissingKey as ex:
                        record_missing_credentials(engineitem)
                        if not args.quiet:
                            output_logger.info(f'A Missing Key error occurred in github-code: {ex}')

                elif engineitem == 'gitlab':
                    try:
                        gitlab_search = gitlabsearch.SearchGitlab(word)
                        stor_lst.append(
                            store(
                                gitlab_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'hackertarget':
                    try:
                        hackertarget_search = hackertarget.SearchHackerTarget(word)
                        stor_lst.append(store(hackertarget_search, engineitem))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'haveibeenpwned':
                    try:
                        haveibeenpwned_search = haveibeenpwned.SearchHaveIBeenPwned(word)
                        stor_lst.append(
                            store(
                                haveibeenpwned_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'hibpverified':
                    try:
                        hibp_search = hibpverified.SearchHibpVerified(word)
                        stor_lst.append(store(hibp_search, engineitem))
                    except MissingKey as error:
                        record_missing_credentials(engineitem)
                        if not args.quiet:
                            output_logger.info(f'A Missing Key error occurred in hibpverified: {error}')
                    except Exception as error:
                        show_default_error_message(engineitem, word, error)

                elif engineitem == 'hudsonrock':
                    try:
                        hudsonrock_search = hudsonrocksearch.SearchHudsonRock(word)
                        stor_lst.append(
                            store(
                                hudsonrock_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        output_logger.info(f'An exception has occurred in Hudson Rock search: {e}')

                elif engineitem == 'hunter':
                    try:
                        hunter_search = huntersearch.SearchHunter(word, limit, start)
                        stor_lst.append(
                            store(
                                hunter_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Hunter: {e}')

                elif engineitem == 'hunterhow':
                    try:
                        hunterhow_search = searchhunterhow.SearchHunterHow(word)
                        stor_lst.append(store(hunterhow_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Hunter How: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in hunterhow search: {e}')

                elif engineitem == 'intelx':
                    try:
                        intelx_search = intelxsearch.SearchIntelx(word)
                        stor_lst.append(
                            store(
                                intelx_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in intelx: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in Intelx search: {e}')

                elif engineitem == 'leakix':
                    try:
                        leakix_search = leakix.SearchLeakix(word)
                        stor_lst.append(
                            store(
                                leakix_search,
                                engineitem,
                            )
                        )
                    except MissingKey as e:
                        record_missing_credentials(engineitem)
                        if not args.quiet:
                            output_logger.info(e)
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'leaklookup':
                    try:
                        leaklookup_search = leaklookup.SearchLeakLookup(word)
                        stor_lst.append(
                            store(
                                leaklookup_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            output_logger.info(f'A Missing Key error occurred in LeakLookup: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in LeakLookup search: {e}')

                elif engineitem == 'mojeek':
                    try:
                        mojeek_search = mojeek.SearchMojeek(word, limit)
                        stor_lst.append(
                            store(
                                mojeek_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            output_logger.info(f'A Missing Key error occurred in Mojeek: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in Mojeek search: {e}')

                elif engineitem == 'netlas':
                    try:
                        netlas_search = netlas.SearchNetlas(word, limit)
                        stor_lst.append(
                            store(
                                netlas_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Netlas: {e}')

                elif engineitem == 'onyphe':
                    try:
                        onyphe_search = onyphe.SearchOnyphe(word)
                        stor_lst.append(
                            store(
                                onyphe_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Onyphe: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Onyphe timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Onyphe returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from Onyphe (missing key): {ke}')
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Onyphe module: {e}')

                elif engineitem == 'otx':
                    try:
                        otxsearch_search = otxsearch.SearchOtx(word)
                        stor_lst.append(
                            store(
                                otxsearch_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing OTX: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to OTX timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'OTX returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from OTX (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in OTX module: {e}')

                elif engineitem == 'pentesttools':
                    try:
                        pentesttools_search = pentesttools.SearchPentestTools(word)
                        stor_lst.append(store(pentesttools_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in PentestTools search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in PentestTools search: {e}')

                elif engineitem == 'projectdiscovery':
                    try:
                        projectdiscovery_search = projectdiscovery.SearchDiscovery(word)
                        stor_lst.append(store(projectdiscovery_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in ProjectDiscovery: {e}')
                        else:
                            output_logger.info('An exception has occurred in ProjectDiscovery')

                elif engineitem == 'rapiddns':
                    try:
                        rapiddns_search = rapiddns.SearchRapidDns(word)
                        stor_lst.append(store(rapiddns_search, engineitem))
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing RapidDNS: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to RapidDNS timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'RapidDNS returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from RapidDNS (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in RapidDNS module: {e}')

                elif engineitem == 'robtex':
                    try:
                        robtex_search = robtex.SearchRobtex(word)
                        stor_lst.append(
                            store(
                                robtex_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'rocketreach':
                    try:
                        rocketreach_search = rocketreach.SearchRocketReach(word, limit)
                        stor_lst.append(store(rocketreach_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in RocketReach: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in RocketReach: {e}')

                elif engineitem == 'securityscorecard':
                    try:
                        securityscorecard_search = securityscorecard.SearchSecurityScorecard(word)
                        stor_lst.append(
                            store(
                                securityscorecard_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            output_logger.info(MissingKey('SecurityScorecard'))
                        else:
                            output_logger.info(f'An exception has occurred in SecurityScorecard search: {e}')

                elif engineitem == 'securityTrails':
                    try:
                        securitytrails_search = securitytrailssearch.SearchSecuritytrail(word)
                        stor_lst.append(
                            store(
                                securitytrails_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred Security Trails: {e}')

                elif engineitem == 'sherlockeye':
                    try:
                        sherlockeye_search = sherlockeye.SearchSherlockeye(word)
                        stor_lst.append(
                            store(
                                sherlockeye_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in sherlockeye: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'shodan':
                    try:
                        shodan_search = shodansearch.SearchShodan()

                        # For normal module usage, we need to create a wrapper that works with the store function
                        class ShodanWrapper:
                            def __init__(self, domain, shodan_client):
                                self.word = domain
                                self.hosts = set()
                                self.shodan = shodan_client

                            async def process(self, use_proxy: bool = False):
                                import socket

                                try:
                                    # Resolve domain to IP and search in Shodan
                                    ip = socket.gethostbyname(self.word)
                                    output_logger.info(f'\tSearching Shodan for {ip}')
                                    result = await self.shodan.search_ip(ip)
                                    if ip in result and isinstance(result[ip], dict):
                                        # Add the IP as a host for consistency with other modules
                                        self.hosts.add(ip)

                                        for host in result[ip].get('hostnames', []):
                                            self.hosts.add(host)

                                        output_logger.info(f'Found Shodan data for {ip}')
                                    elif ip in result and isinstance(result[ip], str):
                                        output_logger.info(f'{ip}: {result[ip]}')
                                except Exception as e:
                                    output_logger.info(f'Error in Shodan search: {e}')

                            async def get_hostnames(self):
                                return list(self.hosts)

                        shodan_wrapper = ShodanWrapper(word, shodan_search)
                        stor_lst.append(store(shodan_wrapper, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Shodan search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in Shodan search: {e}')

                elif engineitem == 'shodanInternetDB':
                    try:
                        shodanidb_search = shodan_internetdb.SearchShodanInternetDB(word)
                        stor_lst.append(
                            store(
                                shodanidb_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Shodan InternetDB: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Shodan InternetDB timed out: {te}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Shodan InternetDB module: {e}')

                elif engineitem == 'shodanct':
                    try:
                        shodanct_search = shodanct.SearchShodanCt(word)
                        stor_lst.append(store(shodanct_search, engineitem))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'sourcegraph':
                    sourcegraph_search = sourcegraph.SearchSourcegraph(word, limit)
                    stor_lst.append(store(sourcegraph_search, engineitem))

                elif engineitem == 'subdomaincenter':
                    try:
                        subdomaincenter_search = subdomaincenter.SubdomainCenter(word)
                        stor_lst.append(store(subdomaincenter_search, engineitem))
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing SubdomainCenter: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to SubdomainCenter timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'SubdomainCenter returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from SubdomainCenter (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in SubdomainCenter module: {e}')

                elif engineitem == 'subdomainfinderc99':
                    try:
                        subdomainfinderc99_search = subdomainfinderc99.SearchSubdomainfinderc99(word)
                        stor_lst.append(store(subdomainfinderc99_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Subdomainfinderc99 search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in Subdomainfinderc99 search: {e}')

                elif engineitem == 'thc':
                    try:
                        thc_search = thc.SearchThc(word)
                        stor_lst.append(store(thc_search, engineitem))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'tomba':
                    try:
                        tomba_search = tombasearch.SearchTomba(word, limit, start)
                        stor_lst.append(
                            store(
                                tomba_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Tomba: {e}')

                elif engineitem == 'urlscan':
                    try:
                        urlscan_search = urlscan.SearchUrlscan(word)
                        stor_lst.append(
                            store(
                                urlscan_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Urlscan: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Urlscan timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Urlscan returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from Urlscan (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Urlscan module: {e}')

                elif engineitem == 'virustotal':
                    try:
                        virustotal_search = virustotal.SearchVirustotal(word)
                        stor_lst.append(store(virustotal_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in virustotal search: {e}')

                elif engineitem == 'waybackarchive':
                    try:
                        waybackarchive_search = waybackarchive.SearchWaybackarchive(word, limit)
                        stor_lst.append(
                            store(
                                waybackarchive_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'whoisxml':
                    try:
                        whoisxml_search = whoisxml.SearchWhoisXML(word)
                        stor_lst.append(store(whoisxml_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in whoisxml search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in WhoisXML search: {e}')

                elif engineitem == 'windvane':
                    try:
                        windvane_search = windvane.SearchWindvane(word)
                        stor_lst.append(
                            store(
                                windvane_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'yahoo':
                    try:
                        yahoo_search = yahoosearch.SearchYahoo(word, limit)
                        stor_lst.append(
                            store(
                                yahoo_search,
                                engineitem,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            output_logger.info(f'Network connection error while accessing Yahoo: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            output_logger.info(f'Request to Yahoo timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            output_logger.info(f'Yahoo returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            output_logger.info(f'Unexpected response structure from Yahoo (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            output_logger.info(f'Unexpected error occurred in Yahoo module: {e}')

                elif engineitem == 'zoomeye':
                    try:
                        zoomeye_search = zoomeyesearch.SearchZoomEye(word, limit)
                        stor_lst.append(
                            store(
                                zoomeye_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            record_missing_credentials(engineitem)
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in zoomeye: {e}')

        elif rest_args is not None:
            try:
                rest_args.dns_brute
            except AttributeError:
                output_logger.info('\n[!] Invalid source.\n')
                sys.exit(1)
        else:
            # Print which engines aren't supported
            unsupported_engines = set(engines) - set(Core.get_supportedengines())
            if unsupported_engines:
                output_logger.info(f'The following engines are not supported: {unsupported_engines}')
            output_logger.info('\n[!] Invalid source.\n')
            sys.exit(1)

    async def worker(queue):
        while True:
            # Get a "work item" out of the queue.
            stor = await queue.get()
            try:
                await stor
            except Exception as work_item_error:
                output_logger.info(
                    f'\n An error occurred while processing a "work item": {type(work_item_error).__name__}: {work_item_error}\n'
                )
            finally:
                # Notify the queue that the "work item" has been processed.
                queue.task_done()

    async def handler(lst):
        queue: asyncio.Queue[Awaitable[Any]] = asyncio.Queue()
        for stor_method in lst:
            # enqueue the coroutines
            queue.put_nowait(stor_method)
        # Create three worker tasks to process the queue concurrently.
        tasks = []
        for _i in range(3):
            task = asyncio.create_task(worker(queue))
            tasks.append(task)

        join_task = asyncio.create_task(queue.join())
        try:
            done, _pending = await asyncio.wait((join_task, *tasks), return_when=asyncio.FIRST_COMPLETED)
            finished_workers = [task for task in tasks if task in done]
            if any(task.cancelled() for task in finished_workers):
                raise asyncio.CancelledError
            for task in finished_workers:
                if error := task.exception():
                    raise error
            if finished_workers:
                raise RuntimeError('A source worker stopped before the queue was drained')
            await join_task
        finally:
            join_task.cancel()
            for task in tasks:
                task.cancel()
            await asyncio.gather(join_task, *tasks, return_exceptions=True)
            while not queue.empty():
                pending_work = queue.get_nowait()
                if inspect.iscoroutine(pending_work):
                    pending_work.close()
                queue.task_done()

    try:
        await handler(lst=stor_lst)
    except asyncio.CancelledError:
        record_dns_resolution_execution(handler_cancelled=True)
        await checkpoint_completed_result(committed_sources_only=True)
        await persist_result(finish_completed_result(committed_sources_only=True))
        raise

    recorded_sources = {result.source.casefold() for result in source_executions}
    source_executions.extend(
        SourceExecution(engine, 'skipped', 0, 0, 'SourceDidNotStart')
        for engine in engines
        if engine.casefold() not in recorded_sources
    )
    record_dns_resolution_execution()
    await checkpoint_completed_result()

    recursive_seeds = sorted(_normalize_hosts_for_storage(all_hosts, word)) if recursive_limits is not None else []
    if recursive_limits is not None and not recursive_seeds:
        action_executions.append(
            ActionExecution.finish(
                action='dns-recursive',
                status='skipped',
                duration_ms=0,
                groups={},
                stop_reason='no-input',
            )
        )
        await checkpoint_completed_result()
    elif recursive_limits is not None:
        recursive_started = time.perf_counter()
        try:
            async with AsyncExitStack() as resolver_stack:
                resolvers = []
                for nameserver in sorted(final_dns_resolver_list):
                    resolver = AioDNSResolverVantage(nameserver, word)
                    resolvers.append(resolver)
                    resolver_stack.push_async_callback(resolver.close)
                recursive_result = await discover_recursive_dns(
                    word,
                    recursive_seeds,
                    dnssearch.DNS_NAMES.read_text(encoding='utf-8').splitlines(),
                    resolvers,
                    recursive_limits,
                )
            recursive_finding_evidence = tuple(
                json.dumps(
                    {
                        'addresses': list(finding.records.addresses),
                        'hostname': finding.hostname,
                        'parent': finding.parent,
                        'ptrs': list(finding.ptrs),
                    },
                    separators=(',', ':'),
                    sort_keys=True,
                )
                for finding in recursive_result.findings
            )
            recursive_classification_evidence = tuple(
                json.dumps(
                    {
                        'addressability': classification.addressability.value,
                        'addresses': list(classification.records.addresses),
                        'cnames': list(classification.records.cnames),
                        'hostname': classification.hostname,
                        'parent': classification.parent,
                        'ptrs': list(classification.ptrs),
                    },
                    separators=(',', ':'),
                    sort_keys=True,
                )
                for classification in recursive_result.classifications
            )
            recursive_summary_evidence = (
                json.dumps(
                    {
                        'depth_reached': recursive_result.depth_reached,
                        'query_count': recursive_result.query_count,
                        'stop_reason': recursive_result.stop_reason,
                        'zero_yield_batches': recursive_result.zero_yield_batches,
                    },
                    separators=(',', ':'),
                    sort_keys=True,
                ),
            )
            recursive_hosts = [finding.hostname for finding in recursive_result.findings]
            recursive_ips = [address for finding in recursive_result.findings for address in finding.records.addresses]
            all_hosts.extend(recursive_hosts)
            all_ip.extend(recursive_ips)
            resolved_screenshot_hosts.update(recursive_hosts)
            for finding in recursive_result.findings:
                if finding.records.addresses:
                    full.extend(f'{finding.hostname}:{address}' for address in finding.records.addresses)
                    reported_host_ip_pairs.update((finding.hostname, address) for address in finding.records.addresses)
                else:
                    full.append(finding.hostname)
        except asyncio.CancelledError:
            action_executions.append(
                ActionExecution.finish(
                    action='dns-recursive',
                    status='failed',
                    duration_ms=(time.perf_counter() - recursive_started) * 1000,
                    groups={},
                    error_type='CancelledError',
                    stop_reason='cancelled',
                )
            )
            await checkpoint_completed_result()
            await persist_result(finish_completed_result())
            raise
        except Exception as error:
            action_executions.append(
                ActionExecution.finish(
                    action='dns-recursive',
                    status='failed',
                    duration_ms=(time.perf_counter() - recursive_started) * 1000,
                    groups={},
                    error_type=type(error).__name__,
                )
            )
            await checkpoint_completed_result()
            output_logger.info(f'[!] Recursive DNS discovery failed: {type(error).__name__}')
        else:
            action_executions.append(
                ActionExecution.finish(
                    action='dns-recursive',
                    status='partial' if recursive_result.stop_reason in {'query-limit', 'runtime-limit'} else 'completed',
                    duration_ms=(time.perf_counter() - recursive_started) * 1000,
                    groups={
                        'hostname': recursive_hosts,
                        'ip': recursive_ips,
                        'dns-recursive-finding': recursive_finding_evidence,
                        'dns-recursive-classification': recursive_classification_evidence,
                        'dns-recursive-summary': recursive_summary_evidence,
                    },
                    stop_reason=recursive_result.stop_reason,
                )
            )
            output_logger.info(
                '[*] Recursive DNS: '
                f'hosts={len(recursive_hosts)}; queries={recursive_result.query_count}; '
                f'depth={recursive_result.depth_reached}; stop={recursive_result.stop_reason}'
            )
            await checkpoint_completed_result()

    return_ips: list = []
    if (
        rest_args is not None
        and len(rest_filename) == 0
        and rest_args.dns_brute is False
        and not dnslookup
        and not return_completed_result
        and not vhost_enabled
    ):
        # Indicates user is using REST api but not wanting output to be saved to a file
        # cast to string so Rest API can understand the type
        return_ips.extend([str(ip) for ip in sorted([netaddr.IPAddress(ip.strip()) for ip in set(all_ip)])])
        # return list(set(all_emails)), return_ips, full, '', ''
        all_hosts = sorted_unique(all_hosts)
        if persist_completed_result:
            await persist_result(finish_completed_result())
        result = (
            total_asns,
            list[str](),
            twitter_people_list_tracker,
            linkedin_people_list_tracker,
            list[str](),
            all_urls,
            all_ip,
            all_emails,
            all_hosts,
        )
        return (*result, sorted_unique(all_breaches)) if include_breaches else result
    # Check to see if all_emails and all_hosts are defined.
    try:
        all_emails
    except NameError:
        output_logger.info('\n\n[!] No emails found because all_emails is not defined.\n\n ')
        sys.exit(1)
    try:
        all_hosts
    except NameError:
        output_logger.info('\n\n[!] No hosts found because all_hosts is not defined.\n\n ')
        sys.exit(1)

    # Results
    if len(total_asns) > 0:
        print_section(f'\n[*] ASNS found: {len(total_asns)}', total_asns, '--------------------')
        total_asns = sorted_unique(total_asns)

    if len(twitter_people_list_tracker) == 0 and 'twitter' in engines:
        output_logger.info('\n[*] No Twitter users found.\n\n')
    elif len(twitter_people_list_tracker) >= 1:
        print_section(
            '\n[*] Twitter Users found: ' + str(len(twitter_people_list_tracker)),
            twitter_people_list_tracker,
            '---------------------',
        )
        twitter_people_list_tracker = sorted_unique(twitter_people_list_tracker)

    print_linkedin_people(engines, linkedin_people_list_tracker)
    linkedin_people_list_tracker = sorted_unique(linkedin_people_list_tracker)

    length_urls = len(all_urls)
    if length_urls == 0:
        if len(engines) >= 1 and 'trello' in engines:
            output_logger.info('\n[*] No Trello URLs found.')
    else:
        total = length_urls
        print_section('\n[*] URLs found: ' + str(total), all_urls, '--------------------')
        all_urls = sorted_unique(all_urls)

    if len(all_ip) == 0:
        output_logger.info('\n[*] No IPs found.')
    else:
        output_logger.info('\n[*] IPs found: ' + str(len(all_ip)))
        output_logger.info('-------------------')
        # use netaddr as the list may contain ipv4 and ipv6 addresses
        ip_list = []
        for ip in set(all_ip):
            try:
                ip = ip.strip()
                if len(ip) > 0:
                    if '/' in ip:
                        ip_list.append(str(netaddr.IPNetwork(ip)))
                    else:
                        ip_list.append(str(netaddr.IPAddress(ip)))
            except (netaddr.core.AddrFormatError, ValueError, TypeError) as e:
                output_logger.info(f'An exception has occurred while adding: {ip} to ip_list: {e}')
                continue
        ip_list = list(sorted(ip_list))
        output_logger.info('\n'.join(map(str, ip_list)))
        # Populate host_ip from ip_list for DNS lookup, virtual hosts search, and Shodan search
        host_ip = ip_list

    if len(all_emails) == 0:
        output_logger.info('\n[*] No emails found.')
    else:
        output_logger.info('\n[*] Emails found: ' + str(len(all_emails)))
        output_logger.info('----------------------')
        all_emails = sorted(list(set(all_emails)))
        output_logger.info('\n'.join(all_emails))

    if len(all_people) == 0:
        output_logger.info('\n[*] No people found.')
    else:
        output_logger.info('\n[*] People found: ' + str(len(all_people)))
        output_logger.info('----------------------')
        for person in all_people:
            output_logger.info(person)

    if len(all_hosts) == 0:
        output_logger.info('\n[*] No hosts found.\n\n')
    else:
        if dnsresolve != '':
            temp = set()
            for host in full:
                if ':' in host:
                    # TODO parse addresses and sort them as they are IPs
                    subdomain, addr = host.split(':', 1)
                    if subdomain.endswith(word):
                        temp.add(subdomain + ':' + addr)
                        continue
                if host.endswith(word):
                    temp.add(host)
            full = sorted_unique(temp)
            full.sort(key=lambda el: el.split(':')[0])
            output_logger.info('\n[*] Hosts found: ' + str(len(full)))
            output_logger.info('---------------------')
            for host in full:
                output_logger.info(host)
        else:
            all_hosts = sorted_unique(all_hosts)
            output_logger.info('\n[*] Hosts found: ' + str(len(all_hosts)))
            output_logger.info('---------------------')
            for host in all_hosts:
                output_logger.info(host)

    # DNS brute force
    if dnsbrute and dnsbrute[0] is True:
        dns_brute_started = time.perf_counter()
        output_logger.info('\n[*] Starting DNS brute force.')
        try:
            dns_force = dnssearch.DnsForce(word, final_dns_resolver_list, verbose=True)
            resolved_pair, hosts, ips = await dns_force.run()
        except asyncio.CancelledError:
            action_executions.append(
                ActionExecution.finish(
                    action='dns-brute',
                    status='failed',
                    duration_ms=(time.perf_counter() - dns_brute_started) * 1000,
                    groups={},
                    error_type='CancelledError',
                    stop_reason='cancelled',
                )
            )
            await checkpoint_completed_result()
            await persist_result(finish_completed_result())
            raise
        except Exception as error:
            action_executions.append(
                ActionExecution.finish(
                    action='dns-brute',
                    status='failed',
                    duration_ms=(time.perf_counter() - dns_brute_started) * 1000,
                    groups={},
                    error_type=type(error).__name__,
                )
            )
            await checkpoint_completed_result()
            await persist_result(finish_completed_result())
            raise
        resolved_screenshot_hosts.update(hosts)
        normalized_brute_hosts = _normalize_hosts_for_storage(hosts, word)
        normalized_brute_ips = _normalize_ip_addresses(ips)
        temp = set()
        for host in resolved_pair:
            if ':' in host:
                # TODO parse addresses and sort them as they are IPs
                subdomain, addr = host.split(':', 1)
                if subdomain.endswith(word):
                    # Append to full, so it's within JSON/XML at the end if output file is requested
                    if host not in full:
                        full.append(host)
                        temp.add(subdomain + ':' + addr)
                    if host not in all_hosts:
                        all_hosts.append(host)
                    continue
            if host.endswith(word):
                if host not in full:
                    full.append(host)
                    temp.add(host)
                if host not in all_hosts:
                    all_hosts.append(host)
        output_logger.info('\n[*] Hosts found after DNS brute force:')
        for sub in temp:
            output_logger.info(sub)
        dns_brute_error_count = getattr(dns_force, 'query_error_count', 0)
        dns_brute_error_types: set[str] = set(getattr(dns_force, 'query_error_types', set()))
        dns_brute_status: ExecutionStatus = 'completed'
        if dns_brute_error_count:
            dns_brute_status = 'partial'
        action_executions.append(
            ActionExecution.finish(
                action='dns-brute',
                status=dns_brute_status,
                duration_ms=(time.perf_counter() - dns_brute_started) * 1000,
                groups={'hostname': normalized_brute_hosts, 'ip': normalized_brute_ips},
                error_type=next(iter(sorted(dns_brute_error_types)), None),
                stop_reason='query-errors' if dns_brute_error_count else None,
            )
        )
        await checkpoint_completed_result()
        # Preserve the dedicated utility response after retaining its completed evidence.
        if dnsbrute[1]:
            await persist_result(finish_completed_result())
            return resolved_pair

    # TakeOver Checking
    if takeover_status:
        takeover_started = time.perf_counter()
        output_logger.info('\n[*] Performing subdomain takeover check')
        output_logger.info('\n[*] Subdomain Takeover checking IS ACTIVE RECON')
        if not all_hosts:
            action_executions.append(
                ActionExecution.finish(
                    action='takeover',
                    status='skipped',
                    duration_ms=(time.perf_counter() - takeover_started) * 1000,
                    groups={},
                    stop_reason='no-input',
                )
            )
        else:
            search_take: takeover.TakeOver | None = None

            def normalize_takeover_evidence(results: Mapping[str, object]) -> set[str]:
                return {
                    json.dumps({'matches': matches, 'url': url}, separators=(',', ':'), sort_keys=True)
                    for url, matches in results.items()
                }

            async def collect_takeover_evidence(*, best_effort: bool = False) -> tuple[dict[str, list[dict[str, str]]], set[str]]:
                if search_take is None:
                    return {}, set()
                try:
                    results = await search_take.get_takeover_results()
                except (asyncio.CancelledError, Exception):
                    if not best_effort:
                        raise
                    return {}, set()
                return results, normalize_takeover_evidence(results)

            try:
                search_take = takeover.TakeOver(all_hosts)
                await search_take.populate_fingerprints()
                await search_take.process(proxy=use_proxy)
                takeover_results, takeover_evidence = await collect_takeover_evidence()
            except (asyncio.CancelledError, Exception) as error:
                takeover_results, takeover_evidence = await collect_takeover_evidence(best_effort=True)
                action_executions.append(
                    ActionExecution.finish(
                        action='takeover',
                        status='partial' if takeover_evidence else 'failed',
                        duration_ms=(time.perf_counter() - takeover_started) * 1000,
                        groups={'takeover': takeover_evidence},
                        error_type=type(error).__name__,
                        stop_reason='cancelled' if isinstance(error, asyncio.CancelledError) else 'scan-error',
                    )
                )
                await persist_result(finish_completed_result())
                raise
            assert search_take is not None
            takeover_request_errors = search_take.request_error_count
            takeover_scan_error = search_take.scan_error_type
            takeover_status_value: ExecutionStatus = 'completed'
            if takeover_scan_error:
                takeover_status_value = 'partial' if takeover_evidence else 'failed'
            elif takeover_request_errors:
                takeover_status_value = (
                    'partial' if takeover_evidence or takeover_request_errors < search_take.request_count else 'failed'
                )
            action_executions.append(
                ActionExecution.finish(
                    action='takeover',
                    status=takeover_status_value,
                    duration_ms=(time.perf_counter() - takeover_started) * 1000,
                    groups={'takeover': takeover_evidence},
                    error_type=takeover_scan_error or next(iter(sorted(search_take.request_error_types)), None),
                    stop_reason=('scan-error' if takeover_scan_error else 'request-errors' if takeover_request_errors else None),
                )
            )
        await checkpoint_action_result()
    # DNS reverse lookup
    dnsrev: list = []
    if dnslookup is True:
        dns_lookup_started = time.perf_counter()
        dns_lookup_error_types: set[str] = set()
        output_logger.info('\n[*] Starting active queries for DNSLookup.')

        # reverse each iprange in a separate task
        __reverse_dns_tasks: dict[str, asyncio.Task[None]] = {}
        for entry in host_ip:
            __ip_range = dnssearch.serialize_ip_range(ip=entry, netmask='24')
            if __ip_range and __ip_range not in set(__reverse_dns_tasks.keys()):
                output_logger.info('\n[*] Performing reverse lookup on ' + __ip_range)
                __reverse_dns_tasks[__ip_range] = asyncio.create_task(
                    dnssearch.reverse_all_ips_in_range(
                        iprange=__ip_range,
                        callback=dnssearch.generate_postprocessing_callback(
                            target=word, local_results=dnsrev, overall_results=full
                        ),
                        nameservers=(final_dns_resolver_list if len(final_dns_resolver_list) > 0 else None),
                        error_types=dns_lookup_error_types,
                    )
                )
                # nameservers=list(map(str, dnsserver.split(','))) if dnsserver else None))

        # run all the reversing tasks concurrently
        try:
            await asyncio.gather(*__reverse_dns_tasks.values())
        except (asyncio.CancelledError, Exception) as error:
            for task in __reverse_dns_tasks.values():
                if not task.done():
                    task.cancel()
            await asyncio.gather(*__reverse_dns_tasks.values(), return_exceptions=True)
            normalized_reverse_hosts = _normalize_hosts_for_storage(dnsrev, word)
            action_executions.append(
                ActionExecution.finish(
                    action='dns-lookup',
                    status='partial' if normalized_reverse_hosts else 'failed',
                    duration_ms=(time.perf_counter() - dns_lookup_started) * 1000,
                    groups={'hostname': normalized_reverse_hosts},
                    error_type=type(error).__name__,
                    stop_reason='cancelled' if isinstance(error, asyncio.CancelledError) else None,
                )
            )
            await checkpoint_completed_result(extra_hostnames=dnsrev)
            await persist_result(finish_completed_result(extra_hostnames=dnsrev))
            raise
        output_logger.info('\n[*] Hosts found after reverse lookup (in target domain):')
        output_logger.info('--------------------------------------------------------')
        for xh in dnsrev:
            output_logger.info(xh)
        normalized_reverse_hosts = _normalize_hosts_for_storage(dnsrev, word)
        dns_lookup_status: ExecutionStatus = 'completed'
        dns_lookup_stop_reason = None
        if not __reverse_dns_tasks:
            dns_lookup_status = 'skipped'
            dns_lookup_stop_reason = 'no-input'
        elif dns_lookup_error_types:
            dns_lookup_status = 'partial'
            dns_lookup_stop_reason = 'query-errors'
        action_executions.append(
            ActionExecution.finish(
                action='dns-lookup',
                status=dns_lookup_status,
                duration_ms=(time.perf_counter() - dns_lookup_started) * 1000,
                groups={'hostname': normalized_reverse_hosts},
                error_type=next(iter(sorted(dns_lookup_error_types)), None),
                stop_reason=dns_lookup_stop_reason,
            )
        )
        await checkpoint_completed_result(extra_hostnames=dnsrev)

    if vhost_enabled:
        vhost_started = time.perf_counter()
        assert vhost_limits is not None
        output_logger.info('[*] Virtual-host discovery is P2 direct interaction (active reconnaissance).')
        harvested_action_hosts = {
            observation.value
            for execution in action_executions
            for observation in execution.observations
            if observation.kind == 'hostname'
        }
        harvested_action_ips = {
            observation.value
            for execution in action_executions
            for observation in execution.observations
            if observation.kind == 'ip'
        }
        harvested_candidates = {
            normalized
            for candidate in (*all_hosts, *dnsrev, *harvested_action_hosts)
            if (normalized := normalize_scoped_hostname(candidate, vhost_scope)) and normalized != vhost_scope
        }
        candidates = tuple(sorted(harvested_candidates | set(vhost_candidates)))
        addresses = tuple(
            sorted(
                _normalize_ip_addresses((*all_ip, *harvested_action_ips)),
                key=lambda value: (ip_address(value).version, int(ip_address(value))),
            )
        )
        logger.info(
            'Virtual-host discovery prepared: endpoints=%d; candidates=%d; request-limit=%d; '
            'runtime=%.2fs; timeout=%.2fs; concurrency=%d',
            1 if vhost_endpoint else len(addresses) * 2,
            len(candidates),
            vhost_limits.request_limit,
            vhost_limits.runtime_seconds,
            vhost_limits.timeout_seconds,
            vhost_limits.concurrency,
        )
        try:
            sweep = await discover_harvested_virtual_hosts(
                scope=vhost_scope,
                addresses=addresses,
                candidates=candidates,
                limits=vhost_limits,
                insecure=args.vhost_insecure,
                endpoint_override=vhost_endpoint,
            )
        except asyncio.CancelledError as error:
            if isinstance(error, VirtualHostDiscoveryCancelled):
                vhost_observations.extend(
                    observation for observation in error.result.observations if observation.classification == 'distinct'
                )
            confirmed_vhosts = confirmed_virtual_hostnames()
            action_executions.append(
                ActionExecution.finish(
                    action='vhost',
                    status='partial' if confirmed_vhosts else 'failed',
                    duration_ms=(time.perf_counter() - vhost_started) * 1000,
                    groups={'hostname': confirmed_vhosts},
                    error_type='CancelledError',
                    stop_reason='cancelled',
                )
            )
            await persist_result(finish_completed_result(extra_hostnames=dnsrev))
            raise
        except Exception as error:
            confirmed_vhosts = confirmed_virtual_hostnames()
            action_executions.append(
                ActionExecution.finish(
                    action='vhost',
                    status='partial' if confirmed_vhosts else 'failed',
                    duration_ms=(time.perf_counter() - vhost_started) * 1000,
                    groups={'hostname': confirmed_vhosts},
                    error_type=type(error).__name__,
                    stop_reason='scan-error',
                )
            )
            output_logger.info(f'[!] Virtual-host discovery failed: {type(error).__name__}')
        else:
            vhost_observations.extend(
                observation for observation in sweep.observations if observation.classification == 'distinct'
            )
            confirmed_vhosts = confirmed_virtual_hostnames()
            if sweep.stop_reason in {'no-candidates', 'no-endpoints'}:
                vhost_status: ExecutionStatus = 'skipped'
            elif sweep.stop_reason in {'request-limit', 'runtime-limit'}:
                vhost_status = 'partial'
            elif sweep.scan_error_type or sweep.request_error_count or sweep.stop_reason in {'request-errors', 'scan-error'}:
                vhost_status = 'partial' if confirmed_vhosts else 'failed'
            else:
                vhost_status = 'completed'
            vhost_error_type = sweep.scan_error_type or next(iter(sweep.request_error_types), None)
            action_executions.append(
                ActionExecution.finish(
                    action='vhost',
                    status=vhost_status,
                    duration_ms=(time.perf_counter() - vhost_started) * 1000,
                    groups={'hostname': confirmed_vhosts},
                    error_type=vhost_error_type,
                    stop_reason=sweep.stop_reason,
                )
            )
            output_logger.info(
                f'[*] Virtual hosts: confirmed={len(vhost_observations)}; '
                f'candidate-endpoints={sweep.candidate_endpoint_count}/{sweep.total_candidate_endpoint_count}; '
                f'endpoints={sweep.endpoint_count}/{sweep.total_endpoint_count}; requests={sweep.request_count}; '
                f'stop={sweep.stop_reason}; elapsed={time.perf_counter() - vhost_started:.2f}s'
            )
            stop_hint = {
                'no-candidates': 'No candidate hostnames were available; select hostname-producing sources or add --vhost-candidate.',
                'no-endpoints': 'No literal-IP endpoints were available; select IP-producing sources, enable a DNS action, or use --vhost-endpoint.',
                'request-limit': 'Coverage stopped at the request limit; raise --vhost-request-limit or narrow the scan.',
                'request-errors': 'All requested coverage finished, but one or more requests failed.',
                'runtime-limit': 'Coverage stopped at the runtime limit; raise --vhost-runtime-seconds or narrow the scan.',
                'scan-error': 'Coverage stopped after an endpoint scan failed.',
            }.get(sweep.stop_reason)
            if stop_hint:
                output_logger.info(f'[!] {stop_hint}')
            for observation in vhost_observations:
                output_logger.info(
                    f'{observation.hostname} at {observation.endpoint}: '
                    f'status={observation.status}; signals={",".join(observation.distinct_signals)}'
                )
        await checkpoint_action_result(extra_hostnames=dnsrev)

    # Screenshots
    if len(args.screenshot) > 0:
        screenshot_started = time.perf_counter()
        screen_shotter = ScreenShotter(args.screenshot)

        async def persist_screenshot_cancellation() -> None:
            action_executions.append(
                ActionExecution.finish(
                    action='screenshot',
                    status='partial' if screenshot_artifacts else 'failed',
                    duration_ms=(time.perf_counter() - screenshot_started) * 1000,
                    groups={},
                    artifacts=screenshot_artifacts,
                    error_type='CancelledError',
                    stop_reason='cancelled',
                )
            )
            completed = finish_completed_result(extra_hostnames=dnsrev)
            if completed is None:
                return
            try:
                if completed_result_checkpoint is not None:
                    await completed_result_checkpoint(completed)
            finally:
                await persist_result(completed)

        path_exists = screen_shotter.verify_path()
        # Verify the path exists, if not create it or if user does not create it skips screenshot
        if not path_exists:
            action_executions.append(
                ActionExecution.finish(
                    action='screenshot',
                    status='skipped',
                    duration_ms=(time.perf_counter() - screenshot_started) * 1000,
                    groups={},
                    stop_reason='path-unavailable',
                )
            )
        else:
            try:
                await screen_shotter.verify_installation()
            except asyncio.CancelledError:
                await persist_screenshot_cancellation()
                raise
            output_logger.info(f'\nScreenshots can be found in: {screen_shotter.output}{screen_shotter.slash}')
            output_logger.info('Filtering domains for ones we can reach')
            if not engines:
                unique_resolved_domains = resolved_screenshot_hosts | {word}
            elif dnsresolve != '':
                unique_resolved_domains = resolved_screenshot_hosts
            else:
                # Technically not resolved in this case, which is not ideal
                # You should always use dns resolve when doing screenshotting
                output_logger.info('NOTE for future use cases you should only use screenshotting in tandem with DNS resolving')
                unique_resolved_domains = set(all_hosts)
            reachable_targets: list[tuple[str, str]] = []
            capture_error_types: set[str] = set()
            if len(unique_resolved_domains) > 0:
                # First filter out ones that didn't resolve
                output_logger.info('Attempting to visit unique resolved domains, this is ACTIVE RECON')

                async def visit_screenshot_target(host: str) -> tuple[str, str]:
                    final_url, body = await screen_shotter.visit(host)
                    return host, final_url if body else ''

                async with Pool(10) as pool:
                    try:
                        results = await pool.map(visit_screenshot_target, list(unique_resolved_domains))
                    except asyncio.CancelledError:
                        await persist_screenshot_cancellation()
                        raise
                    reachable_targets = sorted((host, final_url) for host, final_url in results if final_url)

                semaphore = asyncio.Semaphore(3)

                async def capture_screenshot_target(target: tuple[str, str]) -> tuple[str, str, Path]:
                    subject, final_url = target
                    output_path = screen_shotter.screenshot_path(subject)
                    async with semaphore:
                        return subject, await screen_shotter.take_screenshot(final_url, output_path=output_path), output_path

                async def record_screenshot_artifact(subject: str, captured_url: str, screenshot_path: Path) -> None:
                    if not captured_url:
                        capture_error_types.add('CaptureError')
                        return
                    if not await anyio.Path(screenshot_path).is_file():
                        capture_error_types.add('ArtifactMissing')
                        return
                    raw_subject = subject.strip()
                    try:
                        subject_value = str(ip_address(raw_subject))
                        subject_kind: ResultKind = 'ip'
                    except ValueError:
                        parsed_subject = urlsplit(
                            raw_subject if raw_subject.startswith(('http://', 'https://')) else f'https://{raw_subject}'
                        )
                        if not parsed_subject.hostname:
                            capture_error_types.add('InvalidScreenshotURL')
                            return
                        subject_value = parsed_subject.hostname.lower()
                        try:
                            subject_value = str(ip_address(subject_value))
                            subject_kind = 'ip'
                        except ValueError:
                            subject_kind = 'hostname'
                    recorded_subjects = screenshot_ip_addresses if subject_kind == 'ip' else screenshot_hostnames
                    if subject_value in recorded_subjects:
                        return
                    recorded_subjects.add(subject_value)
                    screenshot_bytes = await anyio.Path(screenshot_path).read_bytes()
                    screenshot_artifacts.append(
                        ArtifactReference(
                            kind='screenshot',
                            subject_kind=subject_kind,
                            subject_value=subject_value,
                            path=str(Path(Path(screen_shotter.output).name) / screenshot_path.name),
                            media_type='image/png',
                            size_bytes=len(screenshot_bytes),
                            sha256=hashlib.sha256(screenshot_bytes).hexdigest(),
                            created_at=datetime.now(UTC),
                        )
                    )

                capture_tasks = [asyncio.create_task(capture_screenshot_target(target)) for target in reachable_targets]
                try:
                    for capture_task in asyncio.as_completed(capture_tasks):
                        subject, captured_url, screenshot_path = await capture_task
                        await record_screenshot_artifact(subject, captured_url, screenshot_path)
                except asyncio.CancelledError:
                    for capture_task in capture_tasks:
                        capture_task.cancel()
                    outcomes = await asyncio.gather(*capture_tasks, return_exceptions=True)
                    for outcome in outcomes:
                        if isinstance(outcome, tuple):
                            await record_screenshot_artifact(*outcome)
                    await persist_screenshot_cancellation()
                    raise
                except Exception as ee:
                    for capture_task in capture_tasks:
                        capture_task.cancel()
                    await asyncio.gather(*capture_tasks, return_exceptions=True)
                    capture_error_types.add(type(ee).__name__)
                    output_logger.info(f'An exception has occurred while mapping: {ee}')
            if not unique_resolved_domains:
                screenshot_status: ExecutionStatus = 'skipped'
                screenshot_stop_reason = 'no-input'
            elif not reachable_targets:
                screenshot_status = 'failed'
                screenshot_stop_reason = 'no-reachable-targets'
            elif capture_error_types and screenshot_artifacts:
                screenshot_status = 'partial'
                screenshot_stop_reason = 'capture-errors'
            elif capture_error_types or (reachable_targets and not screenshot_artifacts):
                screenshot_status = 'failed'
                screenshot_stop_reason = 'capture-errors'
            else:
                screenshot_status = 'completed'
                screenshot_stop_reason = None
            action_executions.append(
                ActionExecution.finish(
                    action='screenshot',
                    status=screenshot_status,
                    duration_ms=(time.perf_counter() - screenshot_started) * 1000,
                    groups={},
                    artifacts=screenshot_artifacts,
                    error_type=next(iter(sorted(capture_error_types)), None),
                    stop_reason=screenshot_stop_reason,
                )
            )
            await checkpoint_action_result(extra_hostnames=dnsrev)
            end = time.perf_counter()
            # There is probably an easier way to do this
            total = int(end - screenshot_started)
            mon, sec = divmod(total, 60)
            hr, mon = divmod(mon, 60)
            total_time = f'{mon:02d}:{sec:02d}'
            output_logger.info(f'Finished taking screenshots in {total_time} seconds')
            output_logger.info('[+] Note there may be leftover chrome processes you may have to kill manually\n')

    # Shodan
    shodanres = []
    if shodan is True:
        shodan_started = time.perf_counter()
        shodan_error_types: set[str] = set()
        output_logger.info('[*] Searching Shodan. ')
        try:
            for ip_index, ip in enumerate(host_ip):
                try:
                    output_logger.info('\tSearching for ' + ip)
                    shodan_search = shodansearch.SearchShodan()
                    shodandict = await shodan_search.search_ip(ip)
                    if shodan_search.error_type:
                        shodan_error_types.add(shodan_search.error_type)

                    shodan_result = shodandict.get(ip)
                    # Check if the result is a string (error message)
                    if isinstance(shodan_result, str):
                        output_logger.info(f'{ip}: {shodan_result}')

                    # Process the results if it's a dictionary
                    if isinstance(shodan_result, dict):
                        rowdata = []
                        for _key, value in shodan_result.items():
                            if isinstance(value, int):
                                value = str(value)
                            if isinstance(value, list):
                                value = ', '.join(map(str, value))
                            rowdata.append(value)
                        shodanres.append(rowdata)
                        shodan_evidence.append(
                            json.dumps({'ip': ip, 'result': shodan_result}, separators=(',', ':'), sort_keys=True)
                        )
                        output_logger.info(ujson.dumps(shodan_result, indent=4, sort_keys=True))
                        output_logger.info('\n')
                    if ip_index + 1 < len(host_ip):
                        await asyncio.sleep(5)
                except Exception as ip_error:
                    shodan_error_types.add(type(ip_error).__name__)
                    output_logger.info(f'[SHODAN-error] Error searching {ip}: {type(ip_error).__name__}')
                    continue
        except asyncio.CancelledError:
            action_executions.append(
                ActionExecution.finish(
                    action='shodan',
                    status='partial' if shodan_evidence else 'failed',
                    duration_ms=(time.perf_counter() - shodan_started) * 1000,
                    groups={'shodan': shodan_evidence},
                    error_type='CancelledError',
                    stop_reason='cancelled',
                )
            )
            await persist_result(finish_completed_result(extra_hostnames=dnsrev))
            raise
        shodan_status: ExecutionStatus = 'completed'
        shodan_stop_reason = None
        if not host_ip:
            shodan_status = 'skipped'
            shodan_stop_reason = 'no-input'
        elif shodan_error_types:
            shodan_status = 'partial' if shodan_evidence else 'failed'
            shodan_stop_reason = 'target-errors'
        action_executions.append(
            ActionExecution.finish(
                action='shodan',
                status=shodan_status,
                duration_ms=(time.perf_counter() - shodan_started) * 1000,
                groups={'shodan': shodan_evidence},
                error_type=next(iter(sorted(shodan_error_types)), None),
                stop_reason=shodan_stop_reason,
            )
        )
        await checkpoint_action_result(extra_hostnames=dnsrev)
    else:
        pass

    if filename != '':
        output_logger.info('\n[*] Reporting started.')
        try:
            if len(rest_filename) == 0:
                filename = os.path.splitext(filename)[0] + '.xml'
            else:
                filename = 'theHarvester/app/static/' + os.path.splitext(rest_filename)[0] + '.xml'
            # XML REPORT SECTION
            async with await anyio.open_file(filename, 'w+') as file:
                await file.write('<?xml version="1.0" encoding="UTF-8"?><theHarvester>')
                sanitized_args = [sanitize_for_xml(f'"{arg}"' if ' ' in arg else arg) for arg in sys.argv[1:]]
                await file.write('<cmd>' + ' '.join(sanitized_args) + '</cmd>')
                for email in all_emails:
                    await file.write('<email>' + sanitize_for_xml(email) + '</email>')
                paired_hosts = {host for host, _ip in reported_host_ip_pairs}
                for host, ip in sorted(reported_host_ip_pairs):
                    await file.write(f'<host><ip>{sanitize_for_xml(ip)}</ip><hostname>{sanitize_for_xml(host)}</hostname></host>')
                for x in full:
                    host, ip = x.split(':', 1) if ':' in x else (x, '')
                    if ip and len(ip) > 3:
                        if (host, ip) in reported_host_ip_pairs:
                            continue
                        await file.write(
                            f'<host><ip>{sanitize_for_xml(ip)}</ip><hostname>{sanitize_for_xml(host)}</hostname></host>'
                        )
                    elif host not in paired_hosts:
                        await file.write(f'<host>{sanitize_for_xml(host)}</host>')
                for host in confirmed_virtual_hostnames():
                    await file.write(f'<vhost>{sanitize_for_xml(host)}</vhost>')
                # TODO add Shodan output into XML report
                await file.write('</theHarvester>')
                output_logger.info('[*] XML File saved.')
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as error:
            output_logger.info(f'[!] An error occurred while saving the XML file: {error}')

    # Enhanced code block for API Endpoint scanning feature
    if args.api_scan or 'api_endpoints' in engines:
        api_scan_started = time.perf_counter()
        api_scanner = None

        def collect_api_action_groups(
            scanner: 'api_endpoints.SearchApiEndpoints | None',
            *,
            best_effort: bool = False,
        ) -> tuple[set[str], set[str], dict[ResultKind, Iterable[str]]]:
            endpoints: set[str] = set()
            interesting: set[str] = set()

            def collect(getter: Callable[[], Iterable[str]]) -> set[str]:
                if not best_effort:
                    return set(getter())
                try:
                    return set(getter())
                except Exception:
                    return set()

            if scanner is not None:
                endpoints = collect(scanner.get_found_endpoints)
                interesting = collect(scanner.get_interesting_endpoints)
                if best_effort:
                    endpoints.update(interesting)
            groups: dict[ResultKind, Iterable[str]] = {'url': endpoints | interesting}
            return endpoints, interesting, groups

        try:
            # Define a default wordlist if none is specified
            wordlist = args.wordlist or str(DATA_DIR / 'wordlists' / 'api_endpoints.txt')

            if not await anyio.Path(wordlist).exists():
                output_logger.info(f'\n[!] Wordlist not found: {wordlist}')
                output_logger.info('Creating a basic API wordlist for scanning...')
                # Create a default simple API endpoint list
                basic_endpoints = [
                    '/api',
                    '/api/v1',
                    '/api/v2',
                    '/api/v3',
                    '/graphql',
                    '/swagger',
                    '/docs',
                    '/redoc',
                    '/swagger-ui',
                    '/openapi.json',
                    '/api-docs',
                    '/rest',
                    '/ws',
                    '/swagger-ui.html',
                    '/health',
                    '/status',
                    '/metrics',
                    '/actuator',
                    '/debug',
                ]
                temp_wordlist = str(DATA_DIR / 'wordlists' / 'temp_api_endpoints.txt')
                async with await anyio.open_file(temp_wordlist, 'w') as f:
                    await f.write('\n'.join(basic_endpoints))
                wordlist = temp_wordlist
                output_logger.info(f'Basic API wordlist created with {len(basic_endpoints)} endpoints.')

            output_logger.info(f'\n[*] Starting API endpoint scanning with wordlist: {wordlist}')
            if args.wordlist:
                api_scanner = api_endpoints.SearchApiEndpoints(
                    word=args.domain,
                    wordlist=wordlist,
                    exact_paths=True,
                )
            else:
                api_scanner = api_endpoints.SearchApiEndpoints(word=args.domain, wordlist=wordlist)
            await api_scanner.do_search()

            # Print results
            endpoints_found, interesting_endpoints, api_action_groups = collect_api_action_groups(api_scanner)
            output_logger.info(f'\n[*] API Endpoints found: {len(endpoints_found)}')
            for endpoint in endpoints_found:
                output_logger.info(f'    - {endpoint}')

            output_logger.info(f'\n[*] Interesting endpoints (200, 201, 202): {len(interesting_endpoints)}')
            for endpoint in interesting_endpoints:
                output_logger.info(f'    - {endpoint}')

            auth_required = api_scanner.get_auth_required()
            output_logger.info(f'\n[*] Endpoints requiring authentication: {len(auth_required)}')
            for endpoint in auth_required:
                output_logger.info(f'    - {endpoint}')

            api_versions = api_scanner.get_api_versions()
            output_logger.info(f'\n[*] Detected API versions: {len(api_versions)}')
            for version in api_versions:
                output_logger.info(f'    - {version}')

            rate_limits = api_scanner.get_rate_limits()
            output_logger.info(f'\n[*] Rate limited endpoints: {len(rate_limits)}')
            for endpoint, info in rate_limits.items():
                output_logger.info(f'    - {endpoint} ({info.method})')

            methods = api_scanner.get_methods()
            output_logger.info(f'\n[*] HTTP methods used: {", ".join(methods)}')

            status_codes = api_scanner.get_status_codes()
            output_logger.info(f'\n[*] HTTP status codes encountered: {", ".join(map(str, status_codes))}')

            if endpoints_found or interesting_endpoints:
                all_urls.extend(sorted(endpoints_found | interesting_endpoints))

            api_scan_error = api_scanner.scan_error_type
            api_request_errors = api_scanner.request_error_count
            api_scan_status: ExecutionStatus = 'completed'
            api_error_type = None
            api_stop_reason = None
            if api_scan_error:
                api_scan_status = 'partial' if any(api_action_groups.values()) else 'failed'
                api_error_type = api_scan_error
                api_stop_reason = 'scan-error'
            elif rate_limits:
                api_scan_status = 'rate-limited'
                api_stop_reason = 'rate-limited'
            elif api_request_errors:
                api_scan_status = 'partial'
                api_error_type = next(iter(sorted(api_scanner.request_error_types)), None)
                api_stop_reason = 'request-errors'
            action_executions.append(
                ActionExecution.finish(
                    action='api-scan',
                    status=api_scan_status,
                    duration_ms=(time.perf_counter() - api_scan_started) * 1000,
                    groups=api_action_groups,
                    error_type=api_error_type,
                    stop_reason=api_stop_reason,
                )
            )

            output_logger.info('\n[+] API scanning completed successfully.')

        except asyncio.CancelledError:
            if not any(execution.action == 'api-scan' for execution in action_executions):
                _endpoints, _interesting, api_action_groups = collect_api_action_groups(api_scanner, best_effort=True)
                action_executions.append(
                    ActionExecution.finish(
                        action='api-scan',
                        status='partial' if any(api_action_groups.values()) else 'failed',
                        duration_ms=(time.perf_counter() - api_scan_started) * 1000,
                        groups=api_action_groups,
                        error_type='CancelledError',
                        stop_reason='cancelled',
                    )
                )
            await persist_result(finish_completed_result(extra_hostnames=dnsrev))
            raise
        except Exception as error:
            endpoints_found, _interesting, api_action_groups = collect_api_action_groups(api_scanner, best_effort=True)
            if endpoints_found:
                all_urls.extend(sorted(endpoints_found))
            if not any(execution.action == 'api-scan' for execution in action_executions):
                action_executions.append(
                    ActionExecution.finish(
                        action='api-scan',
                        status='partial' if any(api_action_groups.values()) else 'failed',
                        duration_ms=(time.perf_counter() - api_scan_started) * 1000,
                        groups=api_action_groups,
                        error_type=type(error).__name__,
                        stop_reason='scan-error',
                    )
                )
            if isinstance(error, MissingKey):
                output_logger.info('\n[!] API endpoint scanning could not start because a required key is missing.')
            else:
                output_logger.info(f'\n[!] API endpoint scanning failed with {type(error).__name__}.')
                output_logger.info('    Continuing with the rest of the scan...')

        await checkpoint_action_result(extra_hostnames=dnsrev)

    all_urls = sorted_unique(all_urls)

    if filename != '':
        try:
            # JSON REPORT SECTION
            filename = os.path.splitext(filename)[0] + '.json'
            # create dict with values for JSON output
            json_dict: dict = dict()
            # start by adding the command line arguments
            json_dict['cmd'] = ' '.join([f'"{arg}"' if ' ' in arg else arg for arg in sys.argv[1:]])
            # to determine if a variable exists
            # it should but just a validation check
            if 'ip_list' in locals():
                if all_ip and len(all_ip) >= 1 and ip_list and len(ip_list) > 0:
                    json_dict['ips'] = ip_list

            if len(all_emails) > 0:
                json_dict['emails'] = all_emails

            if dnsresolve != '' and len(full) > 0:
                json_dict['hosts'] = full
            elif len(all_hosts) > 0:
                json_dict['hosts'] = all_hosts
            else:
                json_dict['hosts'] = []

            if virtual_hostnames := confirmed_virtual_hostnames():
                json_dict['vhosts'] = virtual_hostnames

            if len(all_urls) > 0:
                json_dict['urls'] = all_urls

            if len(total_asns) > 0:
                json_dict['asns'] = total_asns

            if len(twitter_people_list_tracker) > 0:
                json_dict['twitter_people'] = twitter_people_list_tracker

            if len(linkedin_people_list_tracker) > 0:
                json_dict['linkedin_people'] = linkedin_people_list_tracker

            if len(all_people) > 0:
                json_dict['people'] = all_people

            if takeover_status and len(takeover_results) > 0:
                json_dict['takeover_results'] = takeover_results

            json_dict['shodan'] = shodanres
            async with await anyio.open_file(filename, 'w+') as fp:
                dumped_json = ujson.dumps(json_dict, sort_keys=True)
                await fp.write(dumped_json)
            output_logger.info('[*] JSON File saved.')
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as er:
            output_logger.info(f'[!] An error occurred while saving the JSON file: {er} ')
        output_logger.info('\n\n')

    completed_result = finish_completed_result(extra_hostnames=dnsrev)

    if filename and completed_result is not None:
        try:
            jsonl_filename = os.path.splitext(filename)[0] + '.jsonl'
            async with await anyio.open_file(jsonl_filename, 'w+', encoding='UTF-8') as fp:
                await fp.write(completed_result.jsonl())
            output_logger.info('[*] JSONL File saved.')
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as error:
            output_logger.info(f'[!] An error occurred while saving the JSONL file: {error}')

    await persist_result(completed_result)

    if rest_args is not None:
        all_hosts = sorted_unique((*all_hosts, *_normalize_hosts_for_storage(dnsrev, word)))
        result = (
            total_asns,
            list[str](),
            twitter_people_list_tracker,
            linkedin_people_list_tracker,
            list[str](),
            all_urls,
            all_ip,
            all_emails,
            all_hosts,
        )
        if include_breaches:
            result_with_breaches = (*result, sorted_unique(all_breaches))
            return (*result_with_breaches, completed_result) if return_completed_result else result_with_breaches
        return (*result, completed_result) if return_completed_result else result
    sys.exit(0)


async def entry_point() -> None:
    try:
        configure_logging(verbose=False)
        Core.banner()
        await start()
    except KeyboardInterrupt:
        output_logger.info('\n\n[!] ctrl+c detected from user, quitting.\n\n ')
    except Exception as error_entry_point:
        output_logger.info(error_entry_point)
        sys.exit(1)
