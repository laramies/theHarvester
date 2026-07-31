import argparse
import asyncio
import logging
import os
import re
import secrets
import string
import sys
import time
import traceback
from collections.abc import Awaitable, Iterable
from contextlib import AsyncExitStack
from typing import Any

import anyio
import netaddr
import ujson
from aiomultiprocess import Pool

from theHarvester.discovery import (
    api_endpoints,
    baidusearch,
    bevigil,
    bitbucket,
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
    shodansearch,
    subdomaincenter,
    subdomainfinderc99,
    takeover,
    thc,
    threatcrowd,
    tombasearch,
    urlscan,
    venacussearch,
    virustotal,
    waybackarchive,
    whoisxml,
    windvane,
    yahoosearch,
    zoomeyesearch,
)
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib import hostchecker, stash
from theHarvester.lib.core import DATA_DIR, Core, show_default_error_message
from theHarvester.lib.dns_validation import AioDnsResolverVantage, DnsValidator
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.output import (
    configure_logging,
    evidence_xml_fragment,
    format_run_terminal,
    legacy_json_result,
    output_logger,
    run_result_jsonl,
    sorted_unique,
)
from theHarvester.lib.run import (
    LegacyHostnameSource,
    RunResult,
    SourceStatus,
    SQLiteRunStore,
    StageFinding,
    StageFindingKind,
    StageResult,
    complete_run,
    execute_run,
    legacy_dns_results,
    legacy_hostnames,
    validate_run,
)
from theHarvester.lib.source_catalog import ResultRoute, get_source_spec
from theHarvester.screenshot.screenshot import ScreenShotter

logger = logging.getLogger(__name__)


def _normalize_hosts_for_storage(discovered_hosts: Iterable[object], target: str) -> set[str]:
    normalized_target = target.strip().lower().removeprefix('www.').rstrip('.')
    return {
        normalized
        for host in discovered_hosts
        if (normalized := normalize_scoped_hostname(host, normalized_target)) and normalized != normalized_target
    }


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


async def start(rest_args: argparse.Namespace | None = None, *, return_evidence_run: bool = False):
    """Main program function"""
    parser = argparse.ArgumentParser(
        description='theHarvester is used to gather open source intelligence (OSINT) on a company or domain.'
    )
    parser.add_argument('-d', '--domain', help='Company name or domain to search.', required=True)
    parser.add_argument(
        '-l',
        '--limit',
        help='Limit the number of search results, default=500.',
        default=500,
        type=int,
    )
    parser.add_argument(
        '-S',
        '--start',
        help='Start with result number X, default=0.',
        default=0,
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
        help=(
            'Perform DNS resolution on subdomains with a resolver list or passed in resolvers. '
            'Exactly three distinct resolvers enable consensus and wildcard validation for migrated sources.'
        ),
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
        '-f',
        '--filename',
        help='Save XML, legacy JSON, and normalized JSONL reports.',
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
        help="""Comma-separated sources or capability selectors: subdomains, emails, ips, asns, urls, people, or all.
                            Sources: baidu, bevigil, bitbucket, brave, bufferoverun,
                            builtwith, censys, certspotter, chaos, commoncrawl, criminalip, crtsh, dehashed, dnsdumpster, duckduckgo, dymo, fofa, fullhunt, github-code,
                            gitlab, hackertarget, haveibeenpwned, hudsonrock, hunter, hunterhow, intelx, leakix, leaklookup, mojeek, netlas, onyphe, otx, pentesttools,
                            projectdiscovery, rapiddns, robtex, rocketreach, securityscorecard, securityTrails, sherlockeye, shodan, shodanInternetDB, subdomaincenter,
                            subdomainfinderc99, thc, threatcrowd, tomba, urlscan, venacus, virustotal, waybackarchive, whoisxml, windvane, yahoo, zoomeye""",
    )

    # determines if the filename is coming from rest api or user
    rest_filename = ''
    # indicates this from the rest API
    if rest_args:
        if rest_args.source and rest_args.source == 'getsources':
            return list(sorted(Core.get_supportedengines()))
        elif rest_args.dns_brute:
            args = rest_args
            dnsbrute = (rest_args.dns_brute, True)
            filename = args.filename
        else:
            args = rest_args
            dnsbrute = (args.dns_brute, False)
            # We need to make sure the filename is random as to not overwrite other files
            filename = args.filename
            alphabet = string.ascii_letters + string.digits
            rest_filename += f'{"".join(secrets.choice(alphabet) for _ in range(32))}_{filename}' if len(filename) != 0 else ''
    else:
        args = parser.parse_args()
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

    all_emails: list = []
    all_hosts: list = []
    all_ip: list = []
    all_people: list[dict[str, str]] = []
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
                        _ = netaddr.IPAddress(line)
                        final_dns_resolver_list.append(line)
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
                    _ = netaddr.IPAddress(item)
                    final_dns_resolver_list.append(item)
                except (netaddr.core.AddrFormatError, ValueError, TypeError) as e:
                    output_logger.info(f'Passed DNS resolver is invalid, skipping: {item} ({e})')

        # if for some reason, there are duplicates
        final_dns_resolver_list = list(dict.fromkeys(final_dns_resolver_list))
        if len(final_dns_resolver_list) == 0:
            output_logger.info('No valid DNS resolvers were parsed from --dns-resolve; continuing without custom resolvers.')

    engines: list = []
    # If the user specifies
    full: list = []
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

    linkedin_people_list_tracker = []
    linkedin_links_tracker = []
    twitter_people_list_tracker = []

    interesting_urls = []
    total_asns = []
    completed_run_result: RunResult | None = None
    stage_results: list[StageResult] = []

    def record_stage_result(
        source: str,
        started: float,
        findings: list[StageFinding] | tuple[StageFinding, ...] = (),
        error: Exception | None = None,
        *,
        source_family: str | None = None,
        execution: Any | None = None,
        is_action: bool = True,
    ) -> None:
        unique_findings = tuple(dict.fromkeys(findings))
        stage_results.append(
            StageResult(
                source=source,
                status=(
                    execution.status
                    if execution is not None
                    else SourceStatus.FAILED
                    if error is not None
                    else SourceStatus.SUCCEEDED
                    if unique_findings
                    else SourceStatus.EMPTY
                ),
                duration_ms=(time.perf_counter() - started) * 1000,
                result_count=execution.result_count if execution is not None else len(findings),
                findings=unique_findings,
                source_family=source_family,
                error_type=(
                    execution.error_type if execution is not None else type(error).__name__ if error is not None else None
                ),
                is_action=is_action,
            )
        )

    async def _store(
        search_engine: Any,
        source: str,
        run_result: RunResult | None = None,
        stage_findings: list[StageFinding] | None = None,
    ):
        """Process a source and persist its declared consolidated result routes.

        :param search_engine: search engine to fetch details from
        :param source: source against which the details (corresponding to the search engine) need to be persisted
        :param run_result: optional completed evidence run for a migrated source
        """
        if run_result is None:
            logger.info(f'Source {source} started')
            try:
                await search_engine.process(use_proxy)
            except Exception:
                logger.exception(f'Source {source} failed')
                raise
        db_stash = stash.StashManager()
        source_spec = get_source_spec(source)
        routes = source_spec.routes

        if source:
            output_logger.info(f'[*] Searching {source[0].upper() + source[1:]}. ')

        if ResultRoute.HOSTS in routes:
            has_dns_validation = run_result is not None and bool(run_result.dns_validations)
            if run_result is not None and run_result.dns_validations:
                resolved_pair, host_names, temp_ips = legacy_dns_results(run_result, source_spec.name)
                all_ip.extend(temp_ips)
                full.extend(resolved_pair)
            elif run_result is not None:
                host_names = legacy_hostnames(run_result, source_spec.name)
            else:
                discovered_hosts = await search_engine.get_hostnames()
                if source == 'intelx':
                    host_names = list(discovered_hosts)
                else:
                    host_names = list(_normalize_hosts_for_storage(discovered_hosts, word))
            if not has_dns_validation:
                if len(final_dns_resolver_list) == 3:
                    full.extend(host_names)
                elif source != 'hackertarget' and source != 'pentesttools' and source != 'rapiddns':
                    # If a source is inside this conditional, it means the hosts returned must be resolved to obtain ip
                    # This should only be checked if --dns-resolve has a wordlist
                    if dnsresolve is None or len(final_dns_resolver_list) > 0:
                        # indicates that -r was passed in if dnsresolve is None
                        full_hosts_checker = hostchecker.Checker(host_names, final_dns_resolver_list)
                        # If full, this is only getting resolved hosts
                        (
                            resolved_pair,
                            _temp_hosts,
                            temp_ips,
                        ) = await full_hosts_checker.check()
                        all_ip.extend(temp_ips)
                        full.extend(resolved_pair)
                        # full.extend(temp_hosts)
                    else:
                        full.extend(host_names)
                else:
                    full.extend(host_names)
            all_hosts.extend(host_names)
            await db_stash.store_all(word, all_hosts, 'host', source)
            if stage_findings is not None:
                stage_findings.extend(StageFinding(StageFindingKind.HOSTNAME, host) for host in host_names)

        if ResultRoute.EMAILS in routes:
            email_list = await search_engine.get_emails()
            all_emails.extend(email_list)
            await db_stash.store_all(word, email_list, 'email', source)
            if stage_findings is not None:
                stage_findings.extend(StageFinding(StageFindingKind.EMAIL, email) for email in email_list)

        if ResultRoute.IPS in routes:
            ips_list = await search_engine.get_ips()
            all_ip.extend(ips_list)
            await db_stash.store_all(word, all_ip, 'ip', source)
            if stage_findings is not None:
                stage_findings.extend(StageFinding(StageFindingKind.IP_ADDRESS, str(ip)) for ip in ips_list)

        if ResultRoute.PEOPLE in routes:
            people_list = await search_engine.get_people()
            all_people.extend(people_list)
            await db_stash.store_all(word, people_list, 'people', source)
            if stage_findings is not None:
                stage_findings.extend(
                    StageFinding(StageFindingKind.PERSON, ujson.dumps(person, sort_keys=True)) for person in people_list
                )

        if ResultRoute.LINKS in routes:
            links = await search_engine.get_links()
            linkedin_links_tracker.extend(links)
            if len(links) > 0:
                await db.store_all(word, links, 'linkedinlinks', source)
            if stage_findings is not None:
                stage_findings.extend(StageFinding(StageFindingKind.URL, link) for link in links)

        if ResultRoute.INTERESTING_URLS in routes:
            iurls = await search_engine.get_interestingurls()
            interesting_urls.extend(iurls)
            if len(iurls) > 0:
                await db.store_all(word, iurls, 'interestingurls', source)
            if stage_findings is not None:
                stage_findings.extend(StageFinding(StageFindingKind.INTERESTING_URL, url) for url in iurls)

        if ResultRoute.ASNS in routes:
            fasns = await search_engine.get_asns()
            total_asns.extend(fasns)
            if len(fasns) > 0:
                await db.store_all(word, fasns, 'asns', source)
            if stage_findings is not None:
                stage_findings.extend(StageFinding(StageFindingKind.ASN, str(asn)) for asn in fasns)
        if run_result is None:
            logger.info(f'Source {source} completed')
            return None
        return next(
            execution for execution in run_result.source_executions if execution.source.casefold() == source_spec.name.casefold()
        )

    def store(
        search_engine: Any,
        source: str,
        run_result: RunResult | None = None,
    ) -> Awaitable[None]:
        async def run_stage() -> None:
            findings: list[StageFinding] = []
            started = time.perf_counter()
            execution = None
            error: Exception | None = None
            try:
                execution = await _store(search_engine, source, run_result, findings)
            except Exception as stage_error:
                error = stage_error
                raise
            finally:
                source_spec = get_source_spec(source)
                record_stage_result(
                    source_spec.name,
                    started,
                    findings,
                    error,
                    source_family=source_spec.family,
                    execution=execution,
                    is_action=False,
                )

        return run_stage()

    stor_lst = []
    evidence_sources: list[LegacyHostnameSource] = []

    async def store_evidence_sources() -> None:
        nonlocal completed_run_result
        run_result = await execute_run(word, tuple(evidence_sources))
        completed_run_result = run_result
        executions = {execution.source: execution for execution in run_result.source_executions}
        for evidence_source in evidence_sources:
            execution = executions[evidence_source.name]
            if execution.status in (SourceStatus.SUCCEEDED, SourceStatus.EMPTY) or execution.observation_count:
                await store(evidence_source.search, evidence_source.legacy_name, run_result)

    async def validate_completed_run(result: RunResult) -> RunResult:
        if len(final_dns_resolver_list) != 3 or not any(entity.addressability is None for entity in result.entities):
            return result
        async with AsyncExitStack() as resolver_stack:
            vantages = []
            for nameserver in final_dns_resolver_list:
                vantage = AioDnsResolverVantage(nameserver)
                vantages.append(vantage)
                resolver_stack.push_async_callback(vantage.close)
            return await validate_run(result, DnsValidator(tuple(vantages)))

    if args.source is not None:
        engines = Core.expand_source_selection(args.source)
        # Iterate through search engines in order
        if set(engines).issubset(Core.get_supportedengines()):
            output_logger.info(f'\n[*] Target: {word} \n')

            for engineitem in engines:
                if engineitem == 'baidu':
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

                elif engineitem == 'bitbucket':
                    try:
                        bitbucket_search = bitbucket.SearchBitBucket(word, limit)
                        stor_lst.append(
                            store(
                                bitbucket_search,
                                engineitem,
                            )
                        )
                    except Exception as ex:
                        if isinstance(ex, MissingKey):
                            output_logger.info(MissingKey('Bitbucket'))
                        else:
                            show_default_error_message(engineitem, word, ex)

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
                        source_spec = get_source_spec(engineitem)
                        evidence_sources.append(
                            LegacyHostnameSource(
                                name=source_spec.name,
                                legacy_name='CRTsh',
                                family=source_spec.family,
                                search=crtsh_search,
                                proxy=use_proxy,
                            )
                        )
                    except Exception as e:
                        output_logger.info(f'[!] A timeout occurred with crtsh, cannot find {args.domain}\n {e}')

                elif engineitem == 'dehashed':
                    try:
                        dehashed_search = search_dehashed.SearchDehashed(word)
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
                        source_spec = get_source_spec(engineitem)
                        evidence_sources.append(
                            LegacyHostnameSource(
                                name=source_spec.name,
                                legacy_name='dnsdb',
                                family=source_spec.family,
                                search=dnsdb_search,
                                proxy=use_proxy,
                            )
                        )
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
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(MissingKey('HaveIBeenPwned'))
                        else:
                            output_logger.info(f'An exception has occurred in HaveIBeenPwned search: {e}')

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
                                        raise RuntimeError(result[ip])
                                except Exception as e:
                                    output_logger.info(f'Error in Shodan search: {e}')
                                    raise

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

                elif engineitem == 'threatcrowd':
                    try:
                        threatcrowd_search = threatcrowd.SearchThreatcrowd(word)
                        stor_lst.append(
                            store(
                                threatcrowd_search,
                                engineitem,
                            )
                        )
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

                elif engineitem == 'venacus':
                    try:
                        venacus_search = venacussearch.SearchVenacus(word=word, limit=limit, offset_doc=start)
                        stor_lst.append(
                            store(
                                venacus_search,
                                engineitem,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                output_logger.info(f'A Missing Key error occurred in venacus search: {e}')
                        else:
                            output_logger.info(f'An exception has occurred in venacus search: {e}')

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

            if evidence_sources:
                stor_lst.append(store_evidence_sources())

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
    if completed_run_result is None:
        completed_run_result = await execute_run(word, ())
    recorded_sources = {result.source.casefold() for result in stage_results}
    recorded_sources.update(execution.source.casefold() for execution in completed_run_result.source_executions)
    for engine in engines:
        if engine.casefold() not in recorded_sources:
            source_spec = get_source_spec(engine)
            stage_results.append(
                StageResult(
                    source=source_spec.name,
                    source_family=source_spec.family,
                    status=SourceStatus.FAILED,
                    duration_ms=0,
                    result_count=0,
                    error_type='SourceDidNotStart',
                )
            )
    provider_stage_count = len(stage_results)
    completed_run_result = complete_run(completed_run_result, stage_results)
    completed_run_result = await validate_completed_run(completed_run_result)
    if completed_run_result.dns_validations:
        full, all_hosts, validated_ips = legacy_dns_results(completed_run_result)
        all_ip.extend(validated_ips)
    total_asns = sorted_unique(total_asns)
    interesting_urls = sorted_unique(interesting_urls)
    twitter_people_list_tracker = sorted_unique(twitter_people_list_tracker)
    linkedin_people_list_tracker = sorted_unique(linkedin_people_list_tracker)
    linkedin_links_tracker = sorted_unique(linkedin_links_tracker)
    all_urls = sorted_unique(all_urls)
    ip_list = []
    for ip in set(all_ip):
        try:
            value = ip.strip()
            if value:
                ip_list.append(str(netaddr.IPNetwork(value) if '/' in value else netaddr.IPAddress(value)))
        except (netaddr.core.AddrFormatError, ValueError, TypeError) as error:
            output_logger.info(f'An exception has occurred while adding: {ip} to ip_list: {error}')
    ip_list.sort()
    host_ip = ip_list
    all_emails = sorted_unique(all_emails)

    if len(all_hosts) > 0:
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
                    if host[:4] == 'www.':
                        if host[4:] in all_hosts or host[4:] in full:
                            temp.add(host[4:])
                            continue
                    temp.add(host)
            full = list(sorted(temp))
            full.sort(key=lambda el: el.split(':')[0])
            for host in full:
                try:
                    if ':' in host:
                        _, addr = host.split(':', 1)
                        await db.store(word, addr, 'ip', 'DNS-resolver')
                except (OSError, RuntimeError, ValueError, TypeError) as e:
                    output_logger.info(f'An exception has occurred while attempting to insert: {host} IP into DB: {e}')
                    continue
        else:
            all_hosts = [host.replace('www.', '') for host in all_hosts if host.replace('www.', '') in all_hosts]
            all_hosts = list(sorted(set(all_hosts)))

    # DNS brute force
    resolved_pair: list[str] = []
    if dnsbrute and dnsbrute[0] is True:
        output_logger.info('\n[*] Starting DNS brute force.')
        stage_started = time.perf_counter()
        try:
            dns_force = dnssearch.DnsForce(word, final_dns_resolver_list, verbose=True)
            resolved_pair, hosts, ips = await dns_force.run()
            record_stage_result(
                'action:dns-brute',
                stage_started,
                [StageFinding(StageFindingKind.HOSTNAME, host) for host in resolved_pair],
            )
        except Exception as error:
            record_stage_result('action:dns-brute', stage_started, error=error)
            output_logger.info(f'[!] DNS brute force failed: {error}')
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
                if host[:4] == 'www.':
                    if host[4:] in all_hosts or host[4:] in full:
                        continue
                if host not in full:
                    full.append(host)
                    temp.add(host)
                if host not in all_hosts:
                    all_hosts.append(host)
        await db.store_all(word, list(sorted(temp)), 'host', 'dns_bruteforce')

    # DNS reverse lookup
    dnsrev: list = []
    if dnslookup is True:
        output_logger.info('\n[*] Starting active queries for DNSLookup.')
        stage_started = time.perf_counter()

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
        results = await asyncio.gather(*__reverse_dns_tasks.values(), return_exceptions=True)
        for result in results:
            if isinstance(result, asyncio.CancelledError):
                raise result
        reverse_error = next((result for result in results if isinstance(result, Exception)), None)
        record_stage_result(
            'action:dns-lookup',
            stage_started,
            [StageFinding(StageFindingKind.HOSTNAME, host) for host in dnsrev],
            reverse_error,
        )
        if reverse_error is not None:
            output_logger.info(f'[!] Reverse DNS lookup failed: {reverse_error}')

    takeover_results = dict()
    # TakeOver Checking
    if takeover_status:
        output_logger.info('\n[*] Performing subdomain takeover check')
        output_logger.info('\n[*] Subdomain Takeover checking IS ACTIVE RECON')
        stage_started = time.perf_counter()
        try:
            search_take = takeover.TakeOver(all_hosts)
            await search_take.populate_fingerprints()
            await search_take.process(proxy=use_proxy)
            takeover_results = await search_take.get_takeover_results()
            record_stage_result(
                'action:take-over',
                stage_started,
                [
                    StageFinding(
                        StageFindingKind.TAKEOVER,
                        str(host),
                        result if isinstance(result, str) else ujson.dumps(result, sort_keys=True),
                    )
                    for host, result in takeover_results.items()
                ],
            )
        except Exception as error:
            record_stage_result('action:take-over', stage_started, error=error)
            output_logger.info(f'[!] Takeover check failed: {error}')

    # Screenshots
    screenshot_tups = []
    screenshot_hosts: list[str] = []
    screenshot_path = getattr(args, 'screenshot', '')
    if len(screenshot_path) > 0:
        stage_started = time.perf_counter()
        screenshot_error: Exception | None = None
        try:
            screen_shotter = ScreenShotter(screenshot_path)
            path_exists = screen_shotter.verify_path()
            # Verify the path exists, if not create it or if user does not create it skips screenshot
            if path_exists:
                await screen_shotter.verify_installation()
                output_logger.info(f'\nScreenshots can be found in: {screen_shotter.output}{screen_shotter.slash}')
                start_time = time.perf_counter()
                output_logger.info('Filtering domains for ones we can reach')
                if dnsresolve is None or len(final_dns_resolver_list) > 0:
                    unique_resolved_domains = {url.split(':')[0] for url in full if ':' in url and 'www.' not in url}
                else:
                    # Technically not resolved in this case, which is not ideal
                    # You should always use dns resolve when doing screenshotting
                    output_logger.info(
                        'NOTE for future use cases you should only use screenshotting in tandem with DNS resolving'
                    )
                    unique_resolved_domains = set(all_hosts)
                if len(unique_resolved_domains) > 0:
                    # First filter out ones that didn't resolve
                    output_logger.info('Attempting to visit unique resolved domains, this is ACTIVE RECON')
                    async with Pool(10) as pool:
                        results = await pool.map(screen_shotter.visit, list(unique_resolved_domains))
                        # Filter out domains that we couldn't connect to
                        unique_resolved_domains_list = list(sorted({tup[0] for tup in results if len(tup[1]) > 0}))
                    async with Pool(3) as pool:
                        output_logger.info(
                            f'Length of unique resolved domains: {len(unique_resolved_domains_list)} chunking now!\n'
                        )
                        # If you have the resources, you could make the function faster by increasing the chunk number
                        chunk_number = 14
                        for chunk in screen_shotter.chunk_list(unique_resolved_domains_list, chunk_number):
                            try:
                                screenshot_tups.extend(await pool.map(screen_shotter.take_screenshot, chunk))
                                screenshot_hosts.extend(chunk)
                            except Exception as ee:
                                screenshot_error = ee
                                output_logger.info(f'An exception has occurred while mapping: {ee}')
                end = time.perf_counter()
                # There is probably an easier way to do this
                total = int(end - start_time)
                mon, sec = divmod(total, 60)
                hr, mon = divmod(mon, 60)
                total_time = f'{mon:02d}:{sec:02d}'
                output_logger.info(f'Finished taking screenshots in {total_time} seconds')
                output_logger.info('[+] Note there may be leftover chrome processes you may have to kill manually\n')
        except Exception as error:
            screenshot_error = error
            output_logger.info(f'[!] Screenshot stage failed: {error}')
        record_stage_result(
            'action:screenshot',
            stage_started,
            [StageFinding(StageFindingKind.SCREENSHOT, host) for host in screenshot_hosts],
            screenshot_error,
        )

    # Shodan
    shodanres = []
    shodan_findings: list[StageFinding] = []
    shodan_errors: list[Exception] = []
    if shodan is True:
        stage_started = time.perf_counter()
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
                        shodan_errors.append(RuntimeError(shodandict[ip]))
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
                        shodan_findings.append(
                            StageFinding(
                                StageFindingKind.SHODAN_RESULT,
                                ip,
                            )
                        )
                except Exception as ip_error:
                    shodan_errors.append(ip_error)
                    output_logger.info(f'[SHODAN-error] Error searching {ip}: {ip_error}')
                    continue
        except Exception as e:
            shodan_errors.append(e)
            output_logger.info(f'[!] An error occurred with Shodan: {e} ')
        record_stage_result(
            'action:shodan',
            stage_started,
            shodan_findings,
            shodan_errors[0] if shodan_errors else None,
        )
    else:
        pass

    # Enhanced code block for API Endpoint scanning feature
    if getattr(args, 'api_scan', False) or 'api_endpoints' in engines:
        stage_started = time.perf_counter()
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

            endpoints_found = api_scanner.get_found_endpoints()
            interesting_endpoints = api_scanner.get_interesting_endpoints()
            auth_required = api_scanner.get_auth_required()
            api_versions = api_scanner.get_api_versions()
            rate_limits = api_scanner.get_rate_limits()
            methods = api_scanner.get_methods()
            status_codes = api_scanner.get_status_codes()

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

            record_stage_result(
                'action:api-scan',
                stage_started,
                [
                    *(
                        StageFinding(StageFindingKind.API_ENDPOINT, endpoint, str(result.status_code))
                        for endpoint, result in endpoints_found.items()
                    ),
                    *(
                        StageFinding(StageFindingKind.INTERESTING_URL, endpoint, str(result.status_code))
                        for endpoint, result in interesting_endpoints.items()
                    ),
                    *(
                        StageFinding(StageFindingKind.API_AUTH_REQUIRED, endpoint, str(result.status_code))
                        for endpoint, result in auth_required.items()
                    ),
                    *(StageFinding(StageFindingKind.API_VERSION, version) for version in sorted(api_versions)),
                    *(
                        StageFinding(StageFindingKind.API_RATE_LIMIT, endpoint, result.method)
                        for endpoint, result in rate_limits.items()
                    ),
                    *(StageFinding(StageFindingKind.HTTP_METHOD, method) for method in sorted(methods)),
                    *(StageFinding(StageFindingKind.HTTP_STATUS_CODE, str(status_code)) for status_code in sorted(status_codes)),
                ],
            )
            output_logger.info('\n[+] API scanning completed successfully.')

        except MissingKey as error:
            record_stage_result('action:api-scan', stage_started, error=error)
            output_logger.info('\n[!] API endpoint scanning requires a wordlist. Use -w to specify a wordlist file.')
            output_logger.info('    Creating a basic wordlist and trying again...')
            # The wordlist creation code above could be used here
        except Exception as e:
            record_stage_result('action:api-scan', stage_started, error=e)
            output_logger.info(f'\n[!] An exception has occurred in API Endpoints scanning: {e}')
            output_logger.info('    Continuing with the rest of the scan...')
            traceback.print_exc()  # More detailed error information for developers

    completed_run_result = complete_run(completed_run_result, stage_results[provider_stage_count:])
    completed_run_result = await validate_completed_run(completed_run_result)
    if completed_run_result.dns_validations:
        full, all_hosts, validated_ips = legacy_dns_results(completed_run_result)
        all_ip.extend(validated_ips)
        ip_list = sorted(set([*ip_list, *validated_ips]))
    await SQLiteRunStore().save(completed_run_result)
    output_logger.info(format_run_terminal(completed_run_result))

    if filename != '':
        output_logger.info('\n[*] Reporting started.')
        report_base = (
            os.path.join('theHarvester/app/static', os.path.splitext(rest_filename)[0])
            if rest_filename
            else os.path.splitext(filename)[0]
        )
        try:
            xml_filename = report_base + '.xml'
            async with await anyio.open_file(xml_filename, 'w+') as file:
                await file.write('<?xml version="1.0" encoding="UTF-8"?><theHarvester>')
                sanitized_args = [sanitize_for_xml(f'"{arg}"' if ' ' in arg else arg) for arg in sys.argv[1:]]
                await file.write('<cmd>' + ' '.join(sanitized_args) + '</cmd>')
                for email in all_emails:
                    await file.write('<email>' + sanitize_for_xml(email) + '</email>')
                for value in full:
                    host, ip = value.split(':', 1) if ':' in value else (value, '')
                    if ip and len(ip) > 3:
                        await file.write(
                            f'<host><ip>{sanitize_for_xml(ip)}</ip><hostname>{sanitize_for_xml(host)}</hostname></host>'
                        )
                    else:
                        await file.write(f'<host>{sanitize_for_xml(host)}</host>')
                for value in vhost:
                    host, ip = value.split(':', 1) if ':' in value else (value, '')
                    if ip and len(ip) > 3:
                        await file.write(
                            f'<vhost><ip>{sanitize_for_xml(ip)} </ip><hostname>{sanitize_for_xml(host)}</hostname></vhost>'
                        )
                    else:
                        await file.write(f'<vhost>{sanitize_for_xml(host)}</vhost>')
                await file.write(evidence_xml_fragment(completed_run_result))
                await file.write('</theHarvester>')
            output_logger.info('[*] XML File saved.')
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as error:
            output_logger.info(f'[!] An error occurred while saving the XML file: {error}')

        try:
            json_dict: dict[str, object] = {
                'cmd': ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in sys.argv[1:]),
                'hosts': (full if dnsresolve is None or (final_dns_resolver_list and full) else all_hosts),
                'shodan': shodanres,
            }
            optional_results = {
                'ips': ip_list if 'ip_list' in locals() else all_ip,
                'emails': all_emails,
                'vhosts': vhost,
                'interesting_urls': interesting_urls,
                'trello_urls': all_urls,
                'asns': total_asns,
                'twitter_people': twitter_people_list_tracker,
                'linkedin_people': linkedin_people_list_tracker,
                'linkedin_links': linkedin_links_tracker,
                'people': all_people,
                'takeover_results': takeover_results if takeover_status else {},
            }
            json_dict.update({key: value for key, value in optional_results.items() if value})
            json_dict = legacy_json_result(completed_run_result, json_dict)
            async with await anyio.open_file(report_base + '.json', 'w+') as file:
                await file.write(ujson.dumps(json_dict, sort_keys=True))
            output_logger.info('[*] JSON File saved.')
            async with await anyio.open_file(report_base + '.jsonl', 'w+') as file:
                await file.write(run_result_jsonl(completed_run_result) + '\n')
            output_logger.info('[*] JSONL File saved.')
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as error:
            output_logger.info(f'[!] An error occurred while saving the JSON files: {error}')
        output_logger.info('\n\n')

    if rest_args is not None:
        if not rest_args.source and rest_args.dns_brute:
            return (resolved_pair, completed_run_result) if return_evidence_run else resolved_pair
        all_hosts = sorted({host.replace('www.', '') for host in all_hosts})
        response = (
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
        return (*response, completed_run_result) if return_evidence_run else response
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
