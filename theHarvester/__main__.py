import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import string
import sys
import time
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import anyio
import netaddr

from theHarvester.discovery import (
    api_endpoints,
    dnssearch,
    shodansearch,
    takeover,
)
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib import hostchecker
from theHarvester.lib.active_evidence import ActionExecution, ActiveEvidence, ArtifactReference
from theHarvester.lib.asn_attribution import AsnAttributionObservation
from theHarvester.lib.completed_result import (
    CompletedResult,
    ExecutionStatus,
    ResultKind,
    ResultObservation,
    SourceExecution,
)
from theHarvester.lib.core import DATA_DIR, Core
from theHarvester.lib.database import ResultStore
from theHarvester.lib.dns_consensus import AioDNSResolverVantage
from theHarvester.lib.enumeration import (
    DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
    DEFAULT_RESULT_LIMIT,
    DEFAULT_RESULT_START,
    DEFAULT_SOURCE_WORKERS,
    EnumerationOptions,
)
from theHarvester.lib.hostnames import normalize_hostname, normalize_scoped_hostname
from theHarvester.lib.output import configure_logging, output_logger, print_linkedin_people, print_section, sorted_unique
from theHarvester.lib.recursive_dns import (
    DEFAULT_RECURSIVE_DNS_QUERY_LIMIT,
    RecursiveDNSLimits,
    discover_recursive_dns,
)
from theHarvester.lib.resolver_selection import DEFAULT_DNS_RESOLVERS, normalize_resolver_addresses
from theHarvester.lib.result_values import normalize_asn, normalize_ip
from theHarvester.lib.routeviews import RouteViewsCancelled, RouteViewsResult, enrich_routeviews
from theHarvester.lib.shodan_evidence import ShodanHostObservation, canonical_shodan_hosts
from theHarvester.lib.source_catalog import (
    SOURCE_SPECS,
    ActivityClass,
    ResultRoute,
    get_source_spec,
    hostname_collection_conflicts,
    resolve_sources,
)
from theHarvester.lib.source_runner import SourceJob, SourceOutcome, SourceRequest, run_source_jobs
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
)
from theHarvester.screenshot.screenshot import ScreenShotter

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterable

    from theHarvester.lib.network_evidence import NetworkObservation
    from theHarvester.lib.takeover_evidence import TakeoverCandidateOutcome

logger = logging.getLogger(__name__)


def _normalize_hosts_for_storage(discovered_hosts: Iterable[object], target: str) -> set[str]:
    canonical_target = normalize_scoped_hostname(target, target)
    return {
        normalized
        for host in discovered_hosts
        if (normalized := normalize_scoped_hostname(host, target)) and normalized != canonical_target
    }


def _normalize_ip_addresses(values: Iterable[object]) -> set[str]:
    addresses: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            addresses.add(normalize_ip(value))
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
    """Run one CLI or transport-neutral enumeration request."""
    parser = argparse.ArgumentParser(
        description='theHarvester is used to gather open source intelligence (OSINT) on a company or domain.'
    )
    parser.add_argument(
        '-d',
        '--domain',
        help='Company name or domain to search, or an explicit ASN/IP/CIDR target for --routeviews.',
        required=True,
    )
    parser.add_argument(
        '-l',
        '--limit',
        help=(
            'Maximum results requested from each source that supports result limits; 0 continues to provider '
            'exhaustion with no local result or page-count cap (default: 500).'
        ),
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
        '-j',
        '--source-workers',
        help='Maximum discovery sources to run at once (default: %(default)s).',
        default=DEFAULT_SOURCE_WORKERS,
        type=int,
    )
    parser.add_argument(
        '-p',
        '--proxies',
        help='Use proxies.yaml for supported discovery-source, Shodan, and takeover requests. Takeover fails closed if no proxy is available.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '--no-hosts',
        help='Exclude hostname results while retaining other result types returned by selected sources.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-s',
        '--shodan',
        help='Query the Shodan Host API for discovered IPs, using configured proxies when enabled.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '--routeviews',
        help=(
            'Enrich discovered IPs with sourced ASN attribution, or an explicitly targeted ASN, IP, or prefix, through '
            'RouteViews. Returned routing relationships do not establish ownership or target scope. Uses authenticated '
            'access when a RouteViews API key is configured.'
        ),
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
        help=(
            'Check discovered hosts for provider-gated takeover indicators. Uses configured DNS resolvers and '
            'wildcard controls, does not follow redirects, and uses configured proxies when enabled. Indicators '
            'are not confirmed takeovers.'
        ),
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-r',
        '--dns-resolve',
        help=(
            'Resolve discovered hostnames. Pass comma-separated resolver IPs or a text file with one IP per line; '
            'omit the value to use defaults. One run-wide phase uses at most 20 hostname jobs; its query and runtime '
            'limits are unlimited by default.'
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
            'Perform PTR lookups across the /24 network containing each discovered IPv4 address. Addresses are '
            'deduplicated; one run-wide phase uses at most 20 active jobs with no default request or runtime ceiling. '
            'This sends active DNS queries.'
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
            return list(sorted(SOURCE_SPECS))
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
    if isinstance(args.source_workers, bool) or not isinstance(args.source_workers, int) or args.source_workers <= 0:
        raise ValueError('--source-workers must be a positive integer')
    collect_hosts = not args.no_hosts
    action_request = {
        'no_hosts': args.no_hosts,
        'shodan': args.shodan,
        'dns_resolve': args.dns_resolve != '',
        'dns_lookup': args.dns_lookup,
        'dns_brute': args.dns_brute,
        'dns_recursive_depth': args.dns_recursive_depth,
        'takeover': args.take_over,
        'screenshot': args.screenshot,
        'vhost': args.vhost,
        'vhost_endpoint': args.vhost_endpoint,
        'vhost_candidates': args.vhost_candidates,
    }
    if conflicts := hostname_collection_conflicts(action_request):
        raise ValueError(f'--no-hosts cannot be combined with: {", ".join(conflicts)}')
    vhost_enabled = args.vhost or bool(args.vhost_endpoint) or bool(args.vhost_candidates)
    vhost_scope = ''
    vhost_endpoint = ''
    vhost_candidates: tuple[str, ...] = ()
    vhost_limits: VirtualHostLimits | None = None
    if vhost_enabled:
        vhost_scope = normalize_hostname(args.domain)
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
            runtime_seconds=getattr(args, 'dns_recursive_runtime_seconds', DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS),
        )

    engines: list = []
    # If the user specifies
    full: list = []
    resolved_hostnames: set[str] = set()
    reported_host_ip_pairs: set[tuple[str, str]] = set()
    ips: list = []
    host_ip: list = []
    limit: int | None = args.limit
    routeviews_enabled = args.routeviews
    shodan = args.shodan
    start: int = args.start
    all_urls: list = []
    vhost_observations: list[VirtualHostObservation] = []
    word: str = args.domain.rstrip('\n')
    explicit_asn_target: str | None = None
    if word.strip()[:2].casefold() == 'as':
        try:
            explicit_asn_target = normalize_asn(word)
            word = explicit_asn_target
        except ValueError:
            pass
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
    shodan_hosts: dict[str, ShodanHostObservation] = {}
    shodan_action_hosts: set[str] = set()
    takeover_results: dict[str, dict[str, object]] = {}
    takeover_outcomes: list[TakeoverCandidateOutcome] = []
    linkedin_people_list_tracker = []
    twitter_people_list_tracker = []
    total_asns = []
    source_executions: list[SourceExecution] = []
    observations: set[ResultObservation] = set()
    action_executions: list[ActionExecution] = []
    network_prefixes: set[str] = set()
    network_observations: list[NetworkObservation] = []
    asn_attributions: list[AsnAttributionObservation] = []
    displayed_asn_attributions: set[AsnAttributionObservation] = set()
    dns_resolution_duration_ms = 0.0
    dns_resolution_ips: set[str] = set()
    dns_resolution_completed_count = 0
    dns_resolution_query_error_count = 0
    dns_resolution_error_types: set[str] = set()
    dns_resolution_failure_types: set[str] = set()
    dns_resolution_cancelled = False
    dns_resolution_stop_reason: str | None = None

    def confirmed_virtual_hostnames() -> list[str]:
        return sorted({observation.hostname for observation in vhost_observations})

    def display_new_asn_attributions() -> None:
        pending = sorted(set(asn_attributions) - displayed_asn_attributions, key=AsnAttributionObservation.sort_key)
        if not pending:
            return
        print_section(
            f'\n[*] ASN organization attributions found: {len(pending)}',
            (
                f'{item.asn} | {item.organization_label} | {item.producer_kind}:{item.producer} | '
                f'{item.subject_kind}:{item.subject_value}'
                for item in pending
            ),
            '------------------------------------',
        )
        displayed_asn_attributions.update(pending)

    def record_shodan_host_observations(
        host_observations: Iterable[ShodanHostObservation],
    ) -> tuple[ShodanHostObservation, ...]:
        canonical_hosts = canonical_shodan_hosts(list(host_observations))
        for host in canonical_hosts:
            existing = shodan_hosts.get(host.ip)
            if existing is not None and existing != host:
                raise ValueError(f'Shodan host {host.ip} has conflicting evidence')
        for host in canonical_hosts:
            if host.ip not in shodan_hosts:
                output_logger.info(
                    json.dumps(
                        {'type': 'shodan-host', 'value': host.ip, 'details': host.to_details()},
                        indent=4,
                        sort_keys=True,
                    )
                )
            shodan_hosts[host.ip] = host
        return canonical_hosts

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
            )
            if collect_hosts
            else (),
            'infostealer': (
                json.dumps(stealer, ensure_ascii=False, separators=(',', ':'), sort_keys=True) for stealer in all_infostealers
            ),
            'ip': _normalize_ip_addresses(all_ip) | screenshot_ip_addresses,
            'language': map(str, all_languages),
            'linkedin-person': map(str, linkedin_people_list_tracker),
            'person': (json.dumps(person, ensure_ascii=False, separators=(',', ':'), sort_keys=True) for person in all_people),
            'prefix': network_prefixes,
            'server': map(str, all_servers),
            'twitter-person': map(str, twitter_people_list_tracker),
            'url': map(str, all_urls),
        }
        if committed_sources_only:
            committed_groups: dict[ResultKind, list[str]] = {}
            for observation in observations:
                committed_groups.setdefault(observation.kind, []).append(observation.value)
            groups = {kind: iter(values) for kind, values in committed_groups.items()}
        elif collect_hosts and extra_hostnames:
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
                network_observations=network_observations,
                asn_attributions=asn_attributions,
                virtual_hosts=vhost_observations if collect_hosts else (),
                shodan_hosts=tuple(shodan_hosts.values()),
                takeover_outcomes=takeover_outcomes,
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
        elif dns_resolution_stop_reason is not None:
            status = 'partial' if dns_resolution_completed_count else 'failed'
            error_type = next(iter(sorted(dns_resolution_error_types)), None)
            stop_reason = dns_resolution_stop_reason
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
                groups={'hostname': resolved_hostnames, 'ip': dns_resolution_ips},
                error_type=error_type,
                stop_reason=stop_reason,
            )
        )

    def commit_source_outcome(outcome: SourceOutcome) -> None:
        source_executions.append(outcome.execution)
        observations.update(outcome.observations)
        asn_attributions.extend(outcome.asn_attributions)
        record_shodan_host_observations(outcome.shodan_hosts)
        reported_host_ip_pairs.update(outcome.reported_host_ip_pairs)
        if not args.quiet:
            if outcome.execution.stop_reason == 'missing-credentials':
                output_logger.info(f'[!] Source {outcome.execution.source} skipped: missing credentials.')
            elif outcome.execution.status in {'failed', 'partial'} and outcome.execution.error_type is not None:
                output_logger.info(
                    f'[!] Source {outcome.execution.source} {outcome.execution.status}: {outcome.execution.error_type}.'
                )
        for observation in outcome.observations:
            if observation.kind == 'hostname':
                all_hosts.append(observation.value)
            elif observation.kind == 'email':
                all_emails.append(observation.value)
            elif observation.kind == 'ip':
                all_ip.append(observation.value)
            elif observation.kind == 'asn':
                total_asns.append(observation.value)
            elif observation.kind == 'breach':
                all_breaches.append(observation.value)
            elif observation.kind == 'person':
                all_people.append(json.loads(observation.value))
            elif observation.kind == 'url':
                all_urls.append(observation.value)
            elif observation.kind == 'framework':
                all_frameworks.append(observation.value)
            elif observation.kind == 'language':
                all_languages.append(observation.value)
            elif observation.kind == 'server':
                all_servers.append(observation.value)
            elif observation.kind == 'cms':
                all_cms.append(observation.value)
            elif observation.kind == 'analytics':
                all_analytics.append(observation.value)
            elif observation.kind == 'infostealer':
                all_infostealers.append(json.loads(observation.value))

    async def finish_source_outcome(outcome: SourceOutcome) -> None:
        try:
            await checkpoint_completed_result(committed_sources_only=True)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            output_logger.info(f'\n An error occurred while committing {outcome.execution.source}: {type(error).__name__}.\n')
        else:
            execution = outcome.execution
            stop_summary = f'; stop={execution.stop_reason}' if execution.stop_reason is not None else ''
            logger.info(
                f'Source {execution.source} finished in {execution.duration_ms / 1000:.2f}s: '
                f'status={execution.status}; results={execution.result_count}{stop_summary}'
            )

    async def resolve_source_hostnames() -> None:
        nonlocal dns_resolution_cancelled, dns_resolution_completed_count
        nonlocal dns_resolution_duration_ms, dns_resolution_query_error_count, dns_resolution_stop_reason

        hostname_observations = tuple(item for item in observations if item.kind == 'hostname')
        if dnsresolve == '':
            full.extend(sorted({item.value for item in hostname_observations}))
            return

        retained_unresolved_hosts = {
            item.value for item in hostname_observations if get_source_spec(item.source).retains_unresolved_hostnames
        }
        full.extend(sorted(retained_unresolved_hosts))
        if dnsresolve is not None and not final_dns_resolver_list:
            return

        host_names = sorted({item.value for item in hostname_observations})
        if not host_names:
            return

        dns_resolution_started = time.perf_counter()
        full_hosts_checker = hostchecker.Checker(host_names, final_dns_resolver_list)

        def retain_results(results: tuple[list[str], list[str], list[str]]) -> None:
            resolved_pair, resolved_hosts, temp_ips = results
            dns_resolution_ips.update(_normalize_ip_addresses(temp_ips))
            all_ip.extend(temp_ips)
            full.extend(resolved_pair)
            resolved_hostnames.update(resolved_hosts)

        try:
            retain_results(await full_hosts_checker.check())
        except asyncio.CancelledError:
            dns_resolution_duration_ms += (time.perf_counter() - dns_resolution_started) * 1000
            dns_resolution_cancelled = True
            if snapshot := getattr(full_hosts_checker, 'snapshot', None):
                retain_results(snapshot())
            dns_resolution_completed_count += getattr(full_hosts_checker, 'completed_count', 0)
            dns_resolution_query_error_count += getattr(full_hosts_checker, 'query_error_count', 0)
            dns_resolution_error_types.update(getattr(full_hosts_checker, 'query_error_types', set()))
            raise
        except Exception as error:
            dns_resolution_duration_ms += (time.perf_counter() - dns_resolution_started) * 1000
            dns_resolution_failure_types.add(type(error).__name__)
            if snapshot := getattr(full_hosts_checker, 'snapshot', None):
                retain_results(snapshot())
            dns_resolution_completed_count += getattr(full_hosts_checker, 'completed_count', 0)
            dns_resolution_query_error_count += getattr(full_hosts_checker, 'query_error_count', 0)
            dns_resolution_error_types.update(getattr(full_hosts_checker, 'query_error_types', set()))
            output_logger.info(f'\n An error occurred while resolving hostnames: {type(error).__name__}: {error}\n')
            return
        dns_resolution_duration_ms += (time.perf_counter() - dns_resolution_started) * 1000
        dns_resolution_completed_count += getattr(full_hosts_checker, 'completed_count', len(host_names))
        dns_resolution_query_error_count += getattr(full_hosts_checker, 'query_error_count', 0)
        dns_resolution_error_types.update(getattr(full_hosts_checker, 'query_error_types', set()))
        dns_resolution_stop_reason = getattr(full_hosts_checker, 'stop_reason', None)

    source_jobs: list[SourceJob] = []
    if args.source is not None:
        engines = resolve_sources(args.source)
        if not collect_hosts:
            hostname_only_engines = [
                engine
                for engine in engines
                if engine in SOURCE_SPECS and get_source_spec(engine).routes == frozenset({ResultRoute.SUBDOMAINS})
            ]
            source_executions.extend(
                SourceExecution(engine, 'skipped', 0, 0, stop_reason='hostname-collection-disabled')
                for engine in hostname_only_engines
            )
            engines = [engine for engine in engines if engine not in hostname_only_engines]
    if explicit_asn_target is not None and (
        not routeviews_enabled
        or engines
        or shodan
        or dnslookup
        or dnsbrute[0]
        or dnsresolve != ''
        or recursive_limits is not None
        or takeover_status
        or args.screenshot
        or args.api_scan
        or vhost_enabled
    ):
        raise ValueError('ASN target requires --routeviews without discovery sources or other actions')
    if routeviews_enabled and not engines and explicit_asn_target is None:
        try:
            ip_network(word, strict=False)
        except ValueError as error:
            raise ValueError('RouteViews hostname target requires a discovery source') from error
    activities = {get_source_spec(engine).activity for engine in engines if engine in SOURCE_SPECS}
    if shodan:
        activities.add(ActivityClass.PASSIVE)
    if routeviews_enabled:
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
        unsupported_engines = set(engines) - set(SOURCE_SPECS)
        if unsupported_engines:
            output_logger.info(f'The following engines are not supported: {unsupported_engines}')
            output_logger.info('\n[!] Invalid source.\n')
            sys.exit(1)
        output_logger.info(f'\n[*] Target: {word} \n')
        source_jobs.extend(SourceJob(SourceRequest(engine, word, limit, start, use_proxy, collect_hosts)) for engine in engines)

    async def handler(jobs: list[SourceJob]) -> tuple[SourceOutcome, ...]:
        def report_source_started(request: SourceRequest) -> None:
            source = request.source
            output_logger.info(f'[*] Searching {source[0].upper() + source[1:]}. ')

        if jobs:
            output_logger.info(
                f'[*] Source workers: requested={args.source_workers}; effective={min(args.source_workers, len(jobs))}.'
            )
        return await run_source_jobs(
            tuple(jobs),
            workers=args.source_workers,
            commit=commit_source_outcome,
            after_commit=finish_source_outcome,
            on_started=report_source_started,
        )

    try:
        await handler(source_jobs)
        await resolve_source_hostnames()
    except asyncio.CancelledError:
        record_dns_resolution_execution(handler_cancelled=True)
        await checkpoint_completed_result(committed_sources_only=True)
        await persist_result(finish_completed_result(committed_sources_only=True))
        raise

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
            resolved_hostnames.update(recursive_hosts)
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
        and not routeviews_enabled
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
    display_new_asn_attributions()

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

    if not collect_hosts:
        all_hosts = []
    elif len(all_hosts) == 0:
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
        resolved_hostnames.update(hosts)
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
        dns_brute_stop_reason = getattr(dns_force, 'stop_reason', None)
        dns_brute_status: ExecutionStatus = 'completed'
        if dns_brute_stop_reason is not None:
            dns_brute_status = 'partial' if getattr(dns_force, 'completed_count', 0) else 'failed'
        elif dns_brute_error_count:
            dns_brute_status = 'partial'
        action_executions.append(
            ActionExecution.finish(
                action='dns-brute',
                status=dns_brute_status,
                duration_ms=(time.perf_counter() - dns_brute_started) * 1000,
                groups={'hostname': normalized_brute_hosts, 'ip': normalized_brute_ips},
                error_type=next(iter(sorted(dns_brute_error_types)), None),
                stop_reason=dns_brute_stop_reason or ('query-errors' if dns_brute_error_count else None),
            )
        )
        await checkpoint_completed_result()
        # Preserve the dedicated utility response after retaining its completed evidence.
        if dnsbrute[1]:
            await persist_result(finish_completed_result())
            return resolved_pair

    if routeviews_enabled:
        routeviews_started = time.perf_counter()
        routeviews_asns = {explicit_asn_target} if explicit_asn_target is not None else set()
        routeviews_network_seeds = {
            attribution.subject_value
            for attribution in asn_attributions
            if attribution.producer_kind == 'source' and attribution.subject_kind == 'ip'
        }
        try:
            routeviews_network_seeds.add(
                str(ip_network(word.strip(), strict=False)) if '/' in word else str(ip_address(word.strip()))
            )
        except ValueError:
            pass

        def record_routeviews_result(result: RouteViewsResult) -> None:
            network_prefixes.update(result.prefixes)
            total_asns.extend(result.origin_asns)
            network_observations.extend(result.observations)
            action_executions.append(
                ActionExecution.finish(
                    action='routeviews',
                    status=result.status,
                    duration_ms=(time.perf_counter() - routeviews_started) * 1000,
                    groups={'asn': result.origin_asns, 'prefix': result.prefixes},
                    error_type=result.error_type,
                    stop_reason=result.stop_reason,
                )
            )

        try:
            routeviews_result = await enrich_routeviews(
                routeviews_asns,
                routeviews_network_seeds,
                api_key=Core.routeviews_key(),
            )
        except RouteViewsCancelled as error:
            record_routeviews_result(error.result)
            cancelled_result = finish_completed_result()
            try:
                if completed_result_checkpoint is not None and cancelled_result is not None:
                    await completed_result_checkpoint(cancelled_result)
            except (asyncio.CancelledError, Exception) as checkpoint_error:
                output_logger.info(f'[!] RouteViews cancellation checkpoint failed: {checkpoint_error}')
            finally:
                await persist_result(cancelled_result)
            raise
        record_routeviews_result(routeviews_result)
        if routeviews_result.prefixes:
            print_section(
                f'\n[*] RouteViews prefixes found: {len(routeviews_result.prefixes)}',
                routeviews_result.prefixes,
                '--------------------',
            )
        output_logger.info(
            '[*] RouteViews: '
            f'prefixes={len(routeviews_result.prefixes)}; origins={len(routeviews_result.origin_asns)}; '
            f'requests={routeviews_result.request_count}; errors={routeviews_result.error_count}; '
            f'status={routeviews_result.status}; stop={routeviews_result.stop_reason or "complete"}'
        )
        await checkpoint_completed_result()

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
            search_take: takeover.TakeoverScanner | None = None

            async def collect_takeover_evidence(*, best_effort: bool = False) -> tuple[dict[str, dict[str, object]], set[str]]:
                if search_take is None:
                    return {}, set()
                try:
                    outcomes = await search_take.get_takeover_outcomes()
                except asyncio.CancelledError, Exception:
                    if not best_effort:
                        raise
                    return {}, set()
                takeover_outcomes[:] = list(outcomes)
                return ({outcome.hostname: outcome.to_details() for outcome in outcomes}, {item.hostname for item in outcomes})

            try:
                search_take = takeover.TakeoverScanner(
                    all_hosts,
                    target=word,
                    nameservers=final_dns_resolver_list or DEFAULT_DNS_RESOLVERS,
                )
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
            takeover_dns_errors = search_take.dns_error_count
            takeover_inconclusive = getattr(search_take, 'inconclusive_count', 0)
            takeover_scan_error = search_take.scan_error_type
            takeover_status_value: ExecutionStatus = 'completed'
            if takeover_scan_error:
                takeover_status_value = 'partial' if takeover_evidence else 'failed'
            elif takeover_inconclusive:
                takeover_status_value = 'failed' if takeover_inconclusive == search_take.candidate_count else 'partial'
            elif takeover_request_errors or takeover_dns_errors:
                takeover_status_value = 'partial'
            action_executions.append(
                ActionExecution.finish(
                    action='takeover',
                    status=takeover_status_value,
                    duration_ms=(time.perf_counter() - takeover_started) * 1000,
                    groups={'takeover': takeover_evidence},
                    error_type=takeover_scan_error or next(iter(sorted(search_take.request_error_types)), None),
                    stop_reason=(
                        search_take.stop_reason
                        or ('request-errors' if takeover_request_errors else 'query-errors' if takeover_dns_errors else None)
                    ),
                )
            )
        await checkpoint_action_result()
    # DNS reverse lookup
    dnsrev: list = []
    if dnslookup is True:
        dns_lookup_started = time.perf_counter()
        dns_lookup_error_types: set[str] = set()
        output_logger.info('\n[*] Starting active queries for DNSLookup.')

        reverse_ranges: set[str] = set()
        for entry in host_ip:
            __ip_range = dnssearch.serialize_ip_range(ip=entry, netmask='24')
            if __ip_range:
                reverse_ranges.add(__ip_range)
        for iprange in sorted(reverse_ranges):
            output_logger.info('\n[*] Performing reverse lookup on ' + iprange)

        reverse_result = None
        try:
            if reverse_ranges:
                reverse_result = await dnssearch.reverse_ip_ranges(
                    tuple(sorted(reverse_ranges)),
                    dnssearch.generate_postprocessing_callback(target=word, local_results=dnsrev, overall_results=full),
                    nameservers=(final_dns_resolver_list or None),
                    error_types=dns_lookup_error_types,
                )
        except (asyncio.CancelledError, Exception) as error:
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
        if not reverse_ranges:
            dns_lookup_status = 'skipped'
            dns_lookup_stop_reason = 'no-input'
        elif reverse_result is not None and reverse_result.stop_reason is not None:
            dns_lookup_status = 'partial' if reverse_result.completed_count else 'failed'
            dns_lookup_stop_reason = reverse_result.stop_reason
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
            output_logger.info(f'\nScreenshots can be found in: {screen_shotter.output}{screen_shotter.slash}')
            output_logger.info('Filtering domains for ones we can reach')
            if not engines:
                unique_resolved_domains = resolved_hostnames | {word}
            elif dnsresolve != '':
                unique_resolved_domains = resolved_hostnames
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

                try:
                    reachable_targets = await screen_shotter.reachable_targets(sorted(unique_resolved_domains))
                    if reachable_targets:
                        await screen_shotter.capture_targets(reachable_targets, record_screenshot_artifact)
                except asyncio.CancelledError:
                    await persist_screenshot_cancellation()
                    raise
                except Exception as ee:
                    capture_error_types.add(type(ee).__name__)
                    output_logger.info(f'An exception has occurred while taking screenshots: {ee}')
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

    # Shodan
    shodanres: list[dict[str, object]] = []
    if shodan is True:
        shodan_started = time.perf_counter()
        shodan_error_types: set[str] = set()
        shodan_asns: set[str] = set()
        shodan_ips: set[str] = set()

        def has_shodan_action_evidence() -> bool:
            return bool(shodan_action_hosts or shodan_asns or shodan_ips)

        output_logger.info('[*] Searching Shodan. ')
        try:
            shodan_search = None
            if host_ip:
                try:
                    shodan_search = shodansearch.SearchShodan()
                except Exception as init_error:
                    shodan_error_types.add(type(init_error).__name__)
                    output_logger.info(f'[SHODAN-error] Error starting Shodan: {type(init_error).__name__}')
            for ip in host_ip:
                if shodan_search is None:
                    break
                try:
                    output_logger.info('\tSearching for ' + ip)
                    shodandict = await shodan_search.search_ip(ip, proxy=use_proxy)
                    get_asn_attributions = getattr(shodan_search, 'get_asn_attributions', None)
                    if get_asn_attributions is not None:
                        collected_attributions = await get_asn_attributions()
                        current_attributions = {
                            attribution for attribution in collected_attributions if attribution.subject_value == ip
                        }
                        asn_attributions.extend(current_attributions)
                        shodan_asns.update(attribution.asn for attribution in current_attributions)
                        shodan_ips.update(attribution.subject_value for attribution in current_attributions)
                        total_asns.extend(attribution.asn for attribution in current_attributions)
                    if shodan_search.error_type:
                        shodan_error_types.add(shodan_search.error_type)

                    shodan_result = shodandict.get(ip)
                    # Check if the result is a string (error message)
                    if isinstance(shodan_result, str):
                        output_logger.info(f'{ip}: {shodan_result}')

                    # Process the results if it's a dictionary
                    if isinstance(shodan_result, dict):
                        current_hosts = record_shodan_host_observations(
                            host for host in await shodan_search.get_shodan_hosts() if host.ip == ip
                        )
                        shodan_action_hosts.update(host.ip for host in current_hosts)
                        shodanres.extend({'value': host.ip, 'details': host.to_details()} for host in current_hosts)
                        output_logger.info('\n')
                except Exception as ip_error:
                    shodan_error_types.add(type(ip_error).__name__)
                    output_logger.info(f'[SHODAN-error] Error searching {ip}: {type(ip_error).__name__}')
                    continue
        except asyncio.CancelledError:
            action_executions.append(
                ActionExecution.finish(
                    action='shodan',
                    status='partial' if has_shodan_action_evidence() else 'failed',
                    duration_ms=(time.perf_counter() - shodan_started) * 1000,
                    groups={'shodan-host': shodan_action_hosts, 'asn': shodan_asns, 'ip': shodan_ips},
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
            shodan_status = 'partial' if has_shodan_action_evidence() else 'failed'
            shodan_stop_reason = 'target-errors'
        action_executions.append(
            ActionExecution.finish(
                action='shodan',
                status=shodan_status,
                duration_ms=(time.perf_counter() - shodan_started) * 1000,
                groups={'shodan-host': shodan_action_hosts, 'asn': shodan_asns, 'ip': shodan_ips},
                error_type=next(iter(sorted(shodan_error_types)), None),
                stop_reason=shodan_stop_reason,
            )
        )
        display_new_asn_attributions()
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
                if collect_hosts:
                    paired_hosts = {host for host, _ip in reported_host_ip_pairs}
                    for host, ip in sorted(reported_host_ip_pairs):
                        await file.write(
                            f'<host><ip>{sanitize_for_xml(ip)}</ip><hostname>{sanitize_for_xml(host)}</hostname></host>'
                        )
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
            scanner: api_endpoints.SearchApiEndpoints | None,
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
            for endpoint in sorted(endpoints_found):
                output_logger.info(f'    - {endpoint}')

            output_logger.info(f'\n[*] Interesting endpoints (200, 201, 202): {len(interesting_endpoints)}')
            for endpoint in sorted(interesting_endpoints):
                output_logger.info(f'    - {endpoint}')

            auth_required = api_scanner.get_auth_required()
            output_logger.info(f'\n[*] Endpoints requiring authentication: {len(auth_required)}')
            for endpoint in sorted(auth_required):
                output_logger.info(f'    - {endpoint}')

            api_versions = api_scanner.get_api_versions()
            output_logger.info(f'\n[*] Detected API versions: {len(api_versions)}')
            for version in sorted(api_versions):
                output_logger.info(f'    - {version}')

            rate_limits = api_scanner.get_rate_limits()
            output_logger.info(f'\n[*] Rate limited endpoints: {len(rate_limits)}')
            for endpoint, info in sorted(rate_limits.items()):
                output_logger.info(f'    - {endpoint} ({info.method})')

            methods = api_scanner.get_methods()
            output_logger.info(f'\n[*] HTTP methods used: {", ".join(sorted(methods))}')

            status_codes = api_scanner.get_status_codes()
            output_logger.info(f'\n[*] HTTP status codes encountered: {", ".join(map(str, sorted(status_codes)))}')

            if endpoints_found or interesting_endpoints:
                all_urls.extend(sorted(endpoints_found | interesting_endpoints))

            api_scan_error = api_scanner.scan_error_type
            api_request_errors = api_scanner.request_error_count
            scanner_stop_reason = getattr(api_scanner, 'stop_reason', None)
            api_scan_status: ExecutionStatus = 'completed'
            api_error_type = None
            api_stop_reason = None
            if api_scan_error:
                api_scan_status = 'partial' if any(api_action_groups.values()) else 'failed'
                api_error_type = api_scan_error
                api_stop_reason = 'scan-error'
            elif scanner_stop_reason in {'request-limit', 'runtime-limit'}:
                api_scan_status = 'partial' if any(api_action_groups.values()) else 'failed'
                api_error_type = next(iter(sorted(api_scanner.request_error_types)), None)
                api_stop_reason = scanner_stop_reason
            elif api_request_errors:
                api_scan_status = 'partial'
                api_error_type = next(iter(sorted(api_scanner.request_error_types)), None)
                api_stop_reason = 'request-errors'
            elif rate_limits:
                api_scan_status = 'rate-limited'
                api_stop_reason = 'rate-limited'
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

            if api_stop_reason is None:
                output_logger.info('\n[+] API scanning completed successfully.')
            else:
                output_logger.info(f'\n[!] API scanning stopped with reason: {api_stop_reason}.')

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

            if collect_hosts:
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

            if network_prefixes:
                json_dict['prefixes'] = sorted(network_prefixes)

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
                dumped_json = json.dumps(json_dict, separators=(',', ':'), sort_keys=True)
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
