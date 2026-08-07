import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import string
import sys
import time
import traceback
from collections.abc import Awaitable, Callable, Iterable
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

import anyio
import netaddr
import ujson
from aiomultiprocess import Pool

from theHarvester.discovery import (
    api_endpoints,
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
from theHarvester.lib import hostchecker, stash
from theHarvester.lib.completed_result import CompletedResult, ResultKind, SourceExecution
from theHarvester.lib.core import DATA_DIR, Core, show_default_error_message
from theHarvester.lib.dns_consensus import AioDNSResolverVantage
from theHarvester.lib.enumeration import (
    DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
    DEFAULT_RESULT_LIMIT,
    DEFAULT_RESULT_START,
    EnumerationOptions,
)
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.output import configure_logging, output_logger, print_linkedin_sections, print_section, sorted_unique
from theHarvester.lib.recursive_dns import (
    DEFAULT_RECURSIVE_DNS_QUERY_LIMIT,
    RecursiveDNSLimits,
    RecursiveDNSResult,
    discover_recursive_dns,
)
from theHarvester.lib.source_catalog import SOURCE_SPECS, ActivityClass, ResultRoute, get_source_spec
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
):
    """Main program function"""
    parser = argparse.ArgumentParser(
        description='theHarvester is used to gather open source intelligence (OSINT) on a company or domain.'
    )
    parser.add_argument('-d', '--domain', help='Company name or domain to search.', required=True)
    parser.add_argument(
        '-l',
        '--limit',
        help='Limit the number of search results, default=500.',
        default=DEFAULT_RESULT_LIMIT,
        type=int,
    )
    parser.add_argument(
        '-S',
        '--start',
        help='Start with result number X, default=0.',
        default=DEFAULT_RESULT_START,
        type=int,
    )
    parser.add_argument(
        '-p',
        '--proxies',
        help='Use proxies for requests, enter proxies in proxies.yaml.',
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
        help='Take screenshots of resolved domains specify output directory: --screenshot output_directory',
        default='',
        type=str,
    )

    parser.add_argument('-e', '--dns-server', help='DNS server to use for lookup.')
    parser.add_argument(
        '-t',
        '--take-over',
        help='Check for takeovers.',
        default=False,
        action='store_true',
    )
    parser.add_argument(
        '-r',
        '--dns-resolve',
        help='Perform DNS resolution on subdomains with a resolver list or passed in resolvers, default False.',
        default='',
        type=str,
        nargs='?',
    )
    parser.add_argument(
        '-n',
        '--dns-lookup',
        help='Enable DNS server lookup, default False.',
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
        help='Recursively discover DNS names beneath currently addressable parents to this depth.',
        default=0,
        type=int,
    )
    parser.add_argument(
        '--dns-recursive-query-limit',
        help='Maximum DNS record queries across resolver vantages for recursive DNS discovery.',
        default=DEFAULT_RECURSIVE_DNS_QUERY_LIMIT,
        type=int,
    )
    parser.add_argument(
        '--dns-recursive-runtime-seconds',
        help='Maximum runtime in seconds for recursive DNS discovery.',
        default=DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
        type=float,
    )
    parser.add_argument(
        '-f',
        '--filename',
        help='Save the results to XML, JSON, and JSONL files.',
        default='',
        type=str,
    )
    parser.add_argument('-w', '--wordlist', help='Specify a wordlist for API endpoint scanning.', default='')
    parser.add_argument('-a', '--api-scan', help='Scan for API endpoints.', action='store_true')
    parser.add_argument(
        '-q',
        '--quiet',
        help='Suppress missing API key warnings and reading the api-keys file.',
        default=False,
        action='store_true',
    )
    parser.add_argument('--verbose', help='Show informational diagnostic messages.', action='store_true')
    parser.add_argument(
        '-b',
        '--source',
        help=(
            'Comma-separated sources or capability selectors: subdomains, emails, ips, asns, urls, people, '
            f'breaches, or all. Sources: {", ".join(sorted(SOURCE_SPECS, key=str.casefold))}'
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
        if args.dns_brute:
            dnsbrute = (args.dns_brute, return_dns_brute_result)
        else:
            dnsbrute = (args.dns_brute, False)
            # We need to make sure the filename is random as to not overwrite other files
            filename: str = args.filename
            alphabet = string.ascii_letters + string.digits
            rest_filename += f'{"".join(secrets.choice(alphabet) for _ in range(32))}_{filename}' if len(filename) != 0 else ''
    else:
        args = EnumerationOptions.from_namespace(parser.parse_args())
        filename = args.filename
        dnsbrute = (args.dns_brute, False)
        configure_logging(verbose=args.verbose)
        if args.verbose:
            logger.info('Verbose logging enabled')
    Core.quiet = getattr(args, 'quiet', False)
    try:
        db = stash.StashManager()
        await db.do_init()
    except (AttributeError, OSError, RuntimeError, ValueError) as init_error:
        if not args.quiet:
            output_logger.info(f'Error initializing StashManager: {init_error}')
        raise ValueError('Failed to initialize StashManager')

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

    all_emails: list = []
    all_hosts: list = []
    all_ip: list = []
    all_people: list[dict[str, str]] = []
    all_infostealers: list[dict[str, object]] = []
    dnslookup = args.dns_lookup
    dnsserver = args.dns_server  # TODO arg is not used anywhere replace with resolvers wordlist arg dnsresolve
    dnsresolve: str | None = args.dns_resolve
    final_dns_resolver_list = []
    if dnsresolve is not None and len(dnsresolve) > 0:
        # Three scenarios:
        # 8.8.8.8
        # 1.1.1.1,8.8.8.8 or 1.1.1.1, 8.8.8.8
        # resolvers.txt
        if await anyio.Path(dnsresolve).exists():
            async with await anyio.open_file(dnsresolve, encoding='UTF-8') as fp:
                async for line in fp:
                    line = line.strip()
                    if len(line) == 0:
                        continue
                    try:
                        final_dns_resolver_list.append(str(netaddr.IPAddress(line)))
                    except (netaddr.core.AddrFormatError, ValueError, TypeError) as e:
                        output_logger.info(f'An exception has occurred while reading from: {dnsresolve}, {e}')
                        output_logger.info(f'Current line: {line}')
        else:
            cleaned = dnsresolve.replace(' ', '')
            resolver_candidates = cleaned.split(',') if ',' in cleaned else [cleaned]
            for item in resolver_candidates:
                if len(item) == 0:
                    continue
                try:
                    # Verify user passed in an IP; this does not validate resolver behavior
                    final_dns_resolver_list.append(str(netaddr.IPAddress(item)))
                except (netaddr.core.AddrFormatError, ValueError, TypeError) as e:
                    output_logger.info(f'Passed DNS resolver is invalid, skipping: {item} ({e})')

        # if for some reason, there are duplicates
        final_dns_resolver_list = sorted(set(final_dns_resolver_list))
        if len(final_dns_resolver_list) == 0:
            output_logger.info('No valid DNS resolvers were parsed from --dns-resolve; continuing without custom resolvers.')

    recursive_depth = getattr(args, 'dns_recursive_depth', 0)
    recursive_limits = None
    if recursive_depth < 0:
        raise ValueError('--dns-recursive-depth cannot be negative')
    if recursive_depth > 0:
        if len(final_dns_resolver_list) != 3:
            raise ValueError('--dns-recursive-depth requires --dns-resolve with exactly three resolver vantages')
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
    vhost: list = []
    word: str = args.domain.rstrip('\n')
    takeover_status = args.take_over
    use_proxy = args.proxies
    linkedin_people_list_tracker: list = []
    linkedin_links_tracker: list = []
    twitter_people_list_tracker: list = []
    interesting_urls: list = []
    total_asns: list = []
    all_breaches: list[str] = []
    all_frameworks: list[str] = []
    all_languages: list[str] = []
    all_servers: list[str] = []
    all_cms: list[str] = []
    all_analytics: list[str] = []
    endpoints_found: set[str] = set()
    screenshot_results: list[str] = []
    shodan_evidence: list[str] = []
    takeover_results: dict[str, list[dict[str, str]]] = {}
    recursive_result: RecursiveDNSResult | None = None

    linkedin_people_list_tracker = []
    linkedin_links_tracker = []
    twitter_people_list_tracker = []

    interesting_urls = []
    total_asns = []
    source_executions: list[SourceExecution] = []

    def finish_completed_result(
        *, extra_hostnames: Iterable[str] = (), virtual_hosts: Iterable[str] = ()
    ) -> CompletedResult | None:
        groups: dict[ResultKind, Iterable[str]] = {
            'analytics': map(str, all_analytics),
            'api-endpoint': map(str, endpoints_found),
            'asn': map(str, total_asns),
            'breach': map(str, all_breaches),
            'cms': map(str, all_cms),
            'dns-recursive-finding': (
                (
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
                if recursive_result is not None
                else ()
            ),
            'dns-recursive-classification': (
                (
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
                if recursive_result is not None
                else ()
            ),
            'dns-recursive-summary': (
                (
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
                if recursive_result is not None
                else ()
            ),
            'email': map(str, all_emails),
            'framework': map(str, all_frameworks),
            'hostname': _normalize_hosts_for_storage(all_hosts, word),
            'infostealer': (
                json.dumps(stealer, ensure_ascii=False, separators=(',', ':'), sort_keys=True) for stealer in all_infostealers
            ),
            'interesting-url': map(str, interesting_urls),
            'ip-address': _normalize_ip_addresses(all_ip),
            'language': map(str, all_languages),
            'linkedin-link': map(str, linkedin_links_tracker),
            'linkedin-person': map(str, linkedin_people_list_tracker),
            'person': (json.dumps(person, ensure_ascii=False, separators=(',', ':'), sort_keys=True) for person in all_people),
            'server': map(str, all_servers),
            'screenshot': map(str, screenshot_results),
            'shodan': shodan_evidence,
            'takeover': (
                json.dumps({'matches': matches, 'url': url}, separators=(',', ':'), sort_keys=True)
                for url, matches in takeover_results.items()
            ),
            'twitter-person': map(str, twitter_people_list_tracker),
            'url': map(str, all_urls),
            'vhost': map(str, virtual_hosts),
        }
        if extra_hostnames:
            groups['hostname'] = _normalize_hosts_for_storage((*all_hosts, *extra_hostnames), word)
        try:
            return CompletedResult.finish(
                target=word,
                started_at=run_started_at,
                completed_at=datetime.now(UTC),
                groups=groups,
                source_executions=source_executions,
            )
        except (ValueError, TypeError) as error:
            output_logger.info(f'[!] An error occurred while completing the result: {error}')
            return None

    async def checkpoint_completed_result(*, extra_hostnames: Iterable[str] = (), virtual_hosts: Iterable[str] = ()) -> None:
        if (
            completed_result_checkpoint is not None
            and (result := finish_completed_result(extra_hostnames=extra_hostnames, virtual_hosts=virtual_hosts)) is not None
        ):
            await completed_result_checkpoint(result)

    async def collect_and_store(
        search_engine: Any,
        source: str,
    ) -> int:
        """Process a source and persist its declared consolidated result routes.

        :param search_engine: search engine to fetch details from
        :param source: source against which the details (corresponding to the search engine) need to be persisted
        """
        await search_engine.process(use_proxy)
        result_count = 0
        db_stash = stash.StashManager()
        routes = get_source_spec(source).routes

        if source:
            output_logger.info(f'[*] Searching {source[0].upper() + source[1:]}. ')

        if ResultRoute.SUBDOMAINS in routes:
            discovered_hosts = await search_engine.get_hostnames()
            host_names = list(_normalize_hosts_for_storage(discovered_hosts, word))
            paired_hosts: set[str] = set()
            result_count += len(host_names)
            if source == 'rapiddns':
                for host, address in await search_engine.get_host_ip_pairs():
                    normalized = normalize_scoped_hostname(host, word)
                    if normalized and normalized in host_names:
                        paired_hosts.add(normalized)
                        reported_host_ip_pairs.add((normalized, address))

            if source != 'hackertarget' and source != 'pentesttools':
                # If a source is inside this conditional, it means the hosts returned must be resolved to obtain ip
                # This should only be checked if --dns-resolve has a wordlist
                if dnsresolve is None or len(final_dns_resolver_list) > 0:
                    # indicates that -r was passed in if dnsresolve is None
                    full_hosts_checker = hostchecker.Checker(
                        [host for host in host_names if host not in paired_hosts], final_dns_resolver_list
                    )
                    # If full, this is only getting resolved hosts
                    (
                        resolved_pair,
                        resolved_hosts,
                        temp_ips,
                    ) = await full_hosts_checker.check()
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
            await db_stash.store_all(word, all_hosts, 'host', source)

        if ResultRoute.EMAILS in routes:
            email_list = await search_engine.get_emails()
            result_count += len(email_list)
            all_emails.extend(email_list)
            await db_stash.store_all(word, email_list, 'email', source)

        if ResultRoute.IPS in routes:
            ips_list = await search_engine.get_ips()
            result_count += len(ips_list)
            all_ip.extend(ips_list)
            await db_stash.store_all(word, ips_list, 'ip', source)

        if ResultRoute.PEOPLE in routes:
            people_list = await search_engine.get_people()
            result_count += len(people_list)
            all_people.extend(people_list)
            await db_stash.store_all(word, people_list, 'people', source)

        if ResultRoute.LINKS in routes:
            links = await search_engine.get_links()
            result_count += len(links)
            linkedin_links_tracker.extend(links)
            if len(links) > 0:
                await db.store_all(word, links, 'linkedinlinks', source)

        if ResultRoute.URLS in routes:
            urls = await search_engine.get_urls()
            result_count += len(urls)
            all_urls.extend(urls)
            if len(urls) > 0:
                await db_stash.store_all(word, urls, 'url', source)

        if ResultRoute.INTERESTING_URLS in routes:
            get_interesting_urls = getattr(search_engine, 'get_interesting_urls', None)
            iurls = await get_interesting_urls() if get_interesting_urls else await search_engine.get_interestingurls()
            result_count += len(iurls)
            interesting_urls.extend(iurls)
            if len(iurls) > 0:
                await db.store_all(word, iurls, 'interestingurls', source)

        if ResultRoute.ASNS in routes:
            fasns = await search_engine.get_asns()
            result_count += len(fasns)
            total_asns.extend(fasns)
            if len(fasns) > 0:
                await db.store_all(word, fasns, 'asns', source)

        if ResultRoute.BREACHES in routes:
            breach_names = await search_engine.get_breach_names()
            result_count += len(breach_names)
            all_breaches.extend(breach_names)
        if source == 'builtwith':
            technology_results = (
                ('get_frameworks', all_frameworks, 'framework'),
                ('get_languages', all_languages, 'language'),
                ('get_servers', all_servers, 'server'),
                ('get_cms', all_cms, 'cms'),
                ('get_analytics', all_analytics, 'analytics'),
            )
            for getter_name, results, result_type in technology_results:
                values = await getattr(search_engine, getter_name)()
                result_count += len(values)
                results.extend(values)
                await db_stash.store_all(word, values, result_type, source)
        if source == 'hudsonrock':
            infostealers = await search_engine.get_infostealers()
            result_count += len(infostealers)
            all_infostealers.extend(infostealers)

        return result_count

    async def store(search_engine: Any, source: str) -> None:
        logger.info(f'Source {source} started')
        started = time.perf_counter()
        try:
            result_count = await collect_and_store(search_engine, source)
        except Exception as error:
            logger.exception(f'Source {source} failed')
            source_executions.append(
                SourceExecution(source, 'failed', (time.perf_counter() - started) * 1000, 0, type(error).__name__)
            )
            await checkpoint_completed_result()
            raise
        source_executions.append(
            SourceExecution(
                source,
                'succeeded' if result_count else 'empty',
                (time.perf_counter() - started) * 1000,
                result_count,
            )
        )
        await checkpoint_completed_result()
        logger.info(f'Source {source} completed')

    stor_lst = []
    if args.source is not None:
        engines = Core.expand_source_selection(args.source)
    activities = {get_source_spec(engine).activity for engine in engines if engine in SOURCE_SPECS}
    if shodan:
        activities.add(ActivityClass.PASSIVE)
    if dnslookup or dnsbrute[0] or dnsresolve != '' or recursive_limits is not None:
        activities.add(ActivityClass.DNS)
    if takeover_status or args.screenshot or args.api_scan:
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
                if engineitem == 'arquivo':
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
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'builtwith':
                    try:
                        builtwith_search = builtwith.SearchBuiltWith(word)
                        stor_lst.append(store(builtwith_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
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
                            if not args.quiet:
                                output_logger.info(f'A Missing key error occurred in criminalip: {e}')
                        else:
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
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in dehashed: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'dnsdb':
                    try:
                        dnsdb_search = dnsdb.SearchDNSDB(word)
                        stor_lst.append(store(dnsdb_search, engineitem))
                    except MissingKey as e:
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
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in Hunter: {e}')

                elif engineitem == 'hunterhow':
                    try:
                        hunterhow_search = searchhunterhow.SearchHunterHow(word)
                        stor_lst.append(store(hunterhow_search, engineitem))
                    except Exception as e:
                        if isinstance(e, MissingKey):
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
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in virustotal search: {e}')

                elif engineitem == 'waybackarchive':
                    try:
                        waybackarchive_search = waybackarchive.SearchWaybackarchive(word)
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
                queue.task_done()
                # Notify the queue that the "work item" has been processed.
            except Exception as work_item_error:
                output_logger.info(
                    f'\n An error occurred while processing a "work item": {type(work_item_error).__name__}: {work_item_error}\n'
                )
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

        # Wait until the queue is fully processed.
        await queue.join()

        # Cancel our worker tasks.
        for task in tasks:
            task.cancel()
        # Wait until all worker tasks are cancelled.
        await asyncio.gather(*tasks, return_exceptions=True)

    await handler(lst=stor_lst)

    recorded_sources = {result.source.casefold() for result in source_executions}
    source_executions.extend(
        SourceExecution(engine, 'skipped', 0, 0, 'SourceDidNotStart')
        for engine in engines
        if engine.casefold() not in recorded_sources
    )
    await checkpoint_completed_result()

    if recursive_limits is not None:
        try:
            async with AsyncExitStack() as resolver_stack:
                resolvers = []
                for nameserver in sorted(final_dns_resolver_list):
                    resolver = AioDNSResolverVantage(nameserver, word)
                    resolvers.append(resolver)
                    resolver_stack.push_async_callback(resolver.close)
                recursive_result = await discover_recursive_dns(
                    word,
                    all_hosts,
                    dnssearch.DNS_NAMES.read_text(encoding='utf-8').splitlines(),
                    resolvers,
                    recursive_limits,
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
            recursive_db = stash.StashManager()
            await recursive_db.store_all(word, recursive_hosts, 'host', 'dns_recursive')
            await recursive_db.store_all(word, recursive_ips, 'ip', 'dns_recursive')
            output_logger.info(
                '[*] Recursive DNS: '
                f'hosts={len(recursive_hosts)}; queries={recursive_result.query_count}; '
                f'depth={recursive_result.depth_reached}; stop={recursive_result.stop_reason}'
            )
            await checkpoint_completed_result()
        except Exception as error:
            output_logger.info(f'[!] Recursive DNS discovery failed: {type(error).__name__}')

    async def persist_result(completed_result: CompletedResult | None) -> None:
        if completed_result is None:
            return
        try:
            completed_db = stash.StashManager()
            await completed_db.store_completed_result(completed_result)
        except Exception as error:
            output_logger.info(f'[!] An error occurred while storing the completed result: {error}')

    return_ips: list = []
    if rest_args is not None and len(rest_filename) == 0 and rest_args.dns_brute is False and not return_completed_result:
        # Indicates user is using REST api but not wanting output to be saved to a file
        # cast to string so Rest API can understand the type
        return_ips.extend([str(ip) for ip in sorted([netaddr.IPAddress(ip.strip()) for ip in set(all_ip)])])
        # return list(set(all_emails)), return_ips, full, '', ''
        all_hosts = sorted_unique(all_hosts)
        if persist_completed_result:
            await persist_result(finish_completed_result())
        result = (
            total_asns,
            interesting_urls,
            twitter_people_list_tracker,
            linkedin_people_list_tracker,
            linkedin_links_tracker,
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

    if len(interesting_urls) > 0:
        print_section(f'\n[*] Interesting Urls found: {len(interesting_urls)}', interesting_urls, '--------------------')
        interesting_urls = sorted_unique(interesting_urls)

    if len(twitter_people_list_tracker) == 0 and 'twitter' in engines:
        output_logger.info('\n[*] No Twitter users found.\n\n')
    elif len(twitter_people_list_tracker) >= 1:
        print_section(
            '\n[*] Twitter Users found: ' + str(len(twitter_people_list_tracker)),
            twitter_people_list_tracker,
            '---------------------',
        )
        twitter_people_list_tracker = sorted_unique(twitter_people_list_tracker)

    print_linkedin_sections(engines, linkedin_people_list_tracker, linkedin_links_tracker)
    linkedin_people_list_tracker = sorted_unique(linkedin_people_list_tracker)
    linkedin_links_tracker = sorted_unique(linkedin_links_tracker)

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
        db = stash.StashManager()
        if dnsresolve is None or len(final_dns_resolver_list) > 0:
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
                try:
                    if ':' in host:
                        _, addr = host.split(':', 1)
                        await db.store(word, addr, 'ip', 'DNS-resolver')
                except (OSError, RuntimeError, ValueError, TypeError) as e:
                    output_logger.info(f'An exception has occurred while attempting to insert: {host} IP into DB: {e}')
                    continue
        else:
            all_hosts = sorted_unique(all_hosts)
            output_logger.info('\n[*] Hosts found: ' + str(len(all_hosts)))
            output_logger.info('---------------------')
            for host in all_hosts:
                output_logger.info(host)

    # DNS brute force
    if dnsbrute and dnsbrute[0] is True:
        output_logger.info('\n[*] Starting DNS brute force.')
        dns_force = dnssearch.DnsForce(word, final_dns_resolver_list, verbose=True)
        resolved_pair, hosts, ips = await dns_force.run()
        resolved_screenshot_hosts.update(hosts)
        # Check if Rest API is being used if so return found hosts
        if dnsbrute[1]:
            return resolved_pair
        db = stash.StashManager()
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
        await db.store_all(word, list(sorted(temp)), 'host', 'dns_bruteforce')
        await checkpoint_completed_result()

    # TakeOver Checking
    if takeover_status:
        output_logger.info('\n[*] Performing subdomain takeover check')
        output_logger.info('\n[*] Subdomain Takeover checking IS ACTIVE RECON')
        if use_proxy:
            output_logger.info('[!] Takeover checks bypass configured proxies so validated target addresses remain pinned')
        search_take = takeover.TakeOver(all_hosts)
        await search_take.populate_fingerprints()
        await search_take.process(proxy=False)
        takeover_results = await search_take.get_takeover_results()
        await checkpoint_completed_result()
    # DNS reverse lookup
    dnsrev: list = []
    if dnslookup is True:
        output_logger.info('\n[*] Starting active queries for DNSLookup.')

        # reverse each iprange in a separate task
        __reverse_dns_tasks: dict = {}
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
                    )
                )
                # nameservers=list(map(str, dnsserver.split(','))) if dnsserver else None))

        # run all the reversing tasks concurrently
        await asyncio.gather(*__reverse_dns_tasks.values())
        output_logger.info('\n[*] Hosts found after reverse lookup (in target domain):')
        output_logger.info('--------------------------------------------------------')
        for xh in dnsrev:
            output_logger.info(xh)
        await checkpoint_completed_result(extra_hostnames=dnsrev)

    # Screenshots
    if len(args.screenshot) > 0:
        screen_shotter = ScreenShotter(args.screenshot)
        path_exists = screen_shotter.verify_path()
        # Verify the path exists, if not create it or if user does not create it skips screenshot
        if path_exists:
            await screen_shotter.verify_installation()
            output_logger.info(f'\nScreenshots can be found in: {screen_shotter.output}{screen_shotter.slash}')
            start_time = time.perf_counter()
            output_logger.info('Filtering domains for ones we can reach')
            if dnsresolve is None or len(final_dns_resolver_list) > 0:
                unique_resolved_domains = resolved_screenshot_hosts
            else:
                # Technically not resolved in this case, which is not ideal
                # You should always use dns resolve when doing screenshotting
                output_logger.info('NOTE for future use cases you should only use screenshotting in tandem with DNS resolving')
                unique_resolved_domains = set(all_hosts)
            if len(unique_resolved_domains) > 0:
                # First filter out ones that didn't resolve
                output_logger.info('Attempting to visit unique resolved domains, this is ACTIVE RECON')
                async with Pool(10) as pool:
                    results = await pool.map(screen_shotter.visit, list(unique_resolved_domains))
                    # Filter out domains that we couldn't connect to
                    unique_resolved_domains_list = list(sorted({tup[0] for tup in results if len(tup[1]) > 0}))
                async with Pool(3) as pool:
                    output_logger.info(f'Length of unique resolved domains: {len(unique_resolved_domains_list)} chunking now!\n')
                    # If you have the resources, you could make the function faster by increasing the chunk number
                    chunk_number = 14
                    for chunk in screen_shotter.chunk_list(unique_resolved_domains_list, chunk_number):
                        try:
                            screenshot_results.extend(
                                result for result in await pool.map(screen_shotter.take_screenshot, chunk) if result
                            )
                            await checkpoint_completed_result(extra_hostnames=dnsrev)
                        except Exception as ee:
                            output_logger.info(f'An exception has occurred while mapping: {ee}')
            end = time.perf_counter()
            # There is probably an easier way to do this
            total = int(end - start_time)
            mon, sec = divmod(total, 60)
            hr, mon = divmod(mon, 60)
            total_time = f'{mon:02d}:{sec:02d}'
            output_logger.info(f'Finished taking screenshots in {total_time} seconds')
            output_logger.info('[+] Note there may be leftover chrome processes you may have to kill manually\n')

    # Shodan
    shodanres = []
    if shodan is True:
        output_logger.info('[*] Searching Shodan. ')
        try:
            for ip in host_ip:
                try:
                    output_logger.info('\tSearching for ' + ip)
                    shodan_search = shodansearch.SearchShodan()
                    shodandict = await shodan_search.search_ip(ip)
                    await asyncio.sleep(5)

                    # Check if the result is a string (error message)
                    if isinstance(shodandict[ip], str):
                        output_logger.info(f'{ip}: {shodandict[ip]}')
                        continue

                    # Process the results if it's a dictionary
                    if isinstance(shodandict[ip], dict):
                        rowdata = []
                        for _key, value in shodandict[ip].items():
                            if isinstance(value, int):
                                value = str(value)
                            if isinstance(value, list):
                                value = ', '.join(map(str, value))
                            rowdata.append(value)
                        shodanres.append(rowdata)
                        shodan_evidence.append(
                            json.dumps({'ip': ip, 'result': shodandict[ip]}, separators=(',', ':'), sort_keys=True)
                        )
                        await checkpoint_completed_result(extra_hostnames=dnsrev)
                        output_logger.info(ujson.dumps(shodandict[ip], indent=4, sort_keys=True))
                        output_logger.info('\n')
                except Exception as ip_error:
                    output_logger.info(f'[SHODAN-error] Error searching {ip}: {ip_error}')
                    continue
        except Exception as e:
            output_logger.info(f'[!] An error occurred with Shodan: {e} ')
    else:
        pass

    if filename != '':
        output_logger.info('\n[*] Reporting started.')
        try:
            if len(rest_filename) == 0:
                filename = filename.rsplit('.', 1)[0] + '.xml'
            else:
                filename = 'theHarvester/app/static/' + rest_filename.rsplit('.', 1)[0] + '.xml'
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
                for x in vhost:
                    host, ip = x.split(':', 1) if ':' in x else (x, '')
                    if ip and len(ip) > 3:
                        await file.write(
                            f'<vhost><ip>{sanitize_for_xml(ip)} </ip><hostname>{sanitize_for_xml(host)}</hostname></vhost>'
                        )
                    else:
                        await file.write(f'<vhost>{sanitize_for_xml(host)}</vhost>')
                # TODO add Shodan output into XML report
                await file.write('</theHarvester>')
                output_logger.info('[*] XML File saved.')
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as error:
            output_logger.info(f'[!] An error occurred while saving the XML file: {error}')

        try:
            # JSON REPORT SECTION
            filename = filename.rsplit('.', 1)[0] + '.json'
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

            if dnsresolve is None or (len(final_dns_resolver_list) > 0 and len(full) > 0):
                json_dict['hosts'] = full
            elif len(all_hosts) > 0:
                json_dict['hosts'] = all_hosts
            else:
                json_dict['hosts'] = []

            if vhost and len(vhost) > 0:
                json_dict['vhosts'] = vhost

            if len(interesting_urls) > 0:
                json_dict['interesting_urls'] = interesting_urls

            if len(all_urls) > 0:
                json_dict['trello_urls'] = all_urls

            if len(total_asns) > 0:
                json_dict['asns'] = total_asns

            if len(twitter_people_list_tracker) > 0:
                json_dict['twitter_people'] = twitter_people_list_tracker

            if len(linkedin_people_list_tracker) > 0:
                json_dict['linkedin_people'] = linkedin_people_list_tracker

            if len(linkedin_links_tracker) > 0:
                json_dict['linkedin_links'] = linkedin_links_tracker

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

    # Enhanced code block for API Endpoint scanning feature
    if args.api_scan or 'api_endpoints' in engines:
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
            api_scanner = api_endpoints.SearchApiEndpoints(word=args.domain, wordlist=wordlist)
            await api_scanner.do_search()

            # Print results
            endpoints_found = set(api_scanner.get_found_endpoints())
            output_logger.info(f'\n[*] API Endpoints found: {len(endpoints_found)}')
            for endpoint in endpoints_found:
                output_logger.info(f'    - {endpoint}')

            interesting_endpoints = api_scanner.get_interesting_endpoints()
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

            # Add results to storage
            db = stash.StashManager()
            await db.store_all(word, endpoints_found, 'api_endpoint', 'api_scan')

            # Use custom database function if available
            try:
                # Try to use the storage module if available
                db_storage = stash.StashManager()
                await db_storage.store_all(word, endpoints_found, 'api_endpoint', 'api_scan')
            except AttributeError:
                output_logger.info('\n[*] No custom database functions found')

            # Add to interesting URLs if any endpoints were found
            if interesting_endpoints:
                new_urls = [f'https://{args.domain}{endpoint}' for endpoint in interesting_endpoints]
                interesting_urls.extend(new_urls)

                # Also add complete domain paths to the interesting_urls list
                all_urls.extend(new_urls)

            output_logger.info('\n[+] API scanning completed successfully.')
            await checkpoint_completed_result(extra_hostnames=dnsrev, virtual_hosts=vhost)

        except MissingKey:
            output_logger.info('\n[!] API endpoint scanning requires a wordlist. Use -w to specify a wordlist file.')
            output_logger.info('    Creating a basic wordlist and trying again...')
            # The wordlist creation code above could be used here
        except Exception as e:
            output_logger.info(f'\n[!] An exception has occurred in API Endpoints scanning: {e}')
            output_logger.info('    Continuing with the rest of the scan...')
            traceback.print_exc()  # More detailed error information for developers

    completed_result = finish_completed_result(extra_hostnames=dnsrev, virtual_hosts=vhost)

    if filename and completed_result is not None:
        try:
            jsonl_filename = filename.rsplit('.', 1)[0] + '.jsonl'
            async with await anyio.open_file(jsonl_filename, 'w+', encoding='UTF-8') as fp:
                await fp.write(completed_result.jsonl())
            output_logger.info('[*] JSONL File saved.')
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as error:
            output_logger.info(f'[!] An error occurred while saving the JSONL file: {error}')

    await persist_result(completed_result)

    if rest_args is not None:
        all_hosts = sorted_unique(all_hosts)
        result = (
            total_asns,
            interesting_urls,
            twitter_people_list_tracker,
            linkedin_people_list_tracker,
            linkedin_links_tracker,
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
