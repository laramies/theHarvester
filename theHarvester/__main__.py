import argparse
import asyncio
import os
import re
import secrets
import string
import sys
import time
import traceback
from typing import TYPE_CHECKING, Any

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
    dnssearch,
    duckduckgosearch,
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
from theHarvester.lib.output import print_linkedin_sections, print_section, sorted_unique
from theHarvester.screenshot.screenshot import ScreenShotter

if TYPE_CHECKING:
    from collections.abc import Awaitable


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


async def start(rest_args: argparse.Namespace | None = None):
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
        '-f',
        '--filename',
        help='Save the results to an XML and JSON file.',
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
    parser.add_argument(
        '-b',
        '--source',
        help="""baidu, bevigil, bitbucket, brave, bufferoverun,
                            builtwith, censys, certspotter, chaos, commoncrawl, criminalip, crtsh, dehashed, dnsdumpster, duckduckgo, fofa, fullhunt, github-code,
                            gitlab, hackertarget, haveibeenpwned, hudsonrock, hunter, hunterhow, intelx, leakix, leaklookup, netlas, onyphe, otx, pentesttools,
                            projectdiscovery, rapiddns, robtex, rocketreach, securityscorecard, securityTrails, shodan, subdomaincenter,
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
        else:
            args = rest_args
            # We need to make sure the filename is random as to not overwrite other files
            filename: str = args.filename
            alphabet = string.ascii_letters + string.digits
            rest_filename += f'{"".join(secrets.choice(alphabet) for _ in range(32))}_{filename}' if len(filename) != 0 else ''
    else:
        args = parser.parse_args()
        filename = args.filename
        dnsbrute = (args.dns_brute, False)
    Core.quiet = getattr(args, 'quiet', False)
    try:
        db = stash.StashManager()
        await db.do_init()
    except Exception:
        raise ValueError('Failed to initialize StashManager')

    if len(filename) > 0:
        if filename.startswith('~/'):
            # Allow home directory expansion but sanitize the rest
            base_path = os.path.expanduser('~')
            sanitized = sanitize_filename(filename[2:])
            filename = os.path.join(base_path, sanitized)
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
    dnsresolve = args.dns_resolve
    final_dns_resolver_list = []
    if dnsresolve is not None and len(dnsresolve) > 0:
        # Three scenarios:
        # 8.8.8.8
        # 1.1.1.1,8.8.8.8 or 1.1.1.1, 8.8.8.8
        # resolvers.txt
        if os.path.exists(dnsresolve):
            with open(dnsresolve, encoding='UTF-8') as fp:
                for line in fp:
                    line = line.strip()
                    try:
                        if len(line) > 0:
                            _ = netaddr.IPAddress(line)
                            final_dns_resolver_list.append(line)
                    except Exception as e:
                        print(f'An exception has occurred while reading from: {dnsresolve}, {e}')
                        print(f'Current line: {line}')
                        return
        else:
            try:
                if ',' in dnsresolve:
                    cleaned = dnsresolve.replace(' ', '')
                    for item in cleaned.split(','):
                        _ = netaddr.IPAddress(item)
                        final_dns_resolver_list.append(item)
                else:
                    # Verify user passed in the actual IP address does not verify if the IP is a resolver just if an IP
                    _ = netaddr.IPAddress(dnsresolve)
                    final_dns_resolver_list.append(dnsresolve)
            except Exception as e:
                print(f'Passed in DNS resolvers are invalid double check, got error: {e}')
                print(f'Dumping resolvers passed in: {e}')
                sys.exit(0)

        # if for some reason, there are duplicates
        final_dns_resolver_list = list(set(final_dns_resolver_list))

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

    async def store(
        search_engine: Any,
        source: str,
        process_param: Any = None,
        store_host: bool = False,
        store_emails: bool = False,
        store_ip: bool = False,
        store_people: bool = False,
        store_links: bool = False,
        store_results: bool = False,
        store_interestingurls: bool = False,
        store_asns: bool = False,
    ) -> None:
        """
        Persist details into the database.
        The details to be stored are controlled by the parameters passed to the method.

        :param search_engine: search engine to fetch details from
        :param source: source against which the details (corresponding to the search engine) need to be persisted
        :param process_param: any parameters to be passed to the search engine eg: Google needs google_dorking
        :param store_host: whether to store hosts
        :param store_emails: whether to store emails
        :param store_ip: whether to store IP address
        :param store_people: whether to store user details
        :param store_links: whether to store links
        :param store_results: whether to fetch details from get_results() and persist
        :param store_interestingurls: whether to store interesting urls
        :param store_asns: whether to store asns
        """
        (
            await search_engine.process(use_proxy)
            if process_param is None
            else await search_engine.process(process_param, use_proxy)
        )
        db_stash = stash.StashManager()

        if source:
            print(f'[*] Searching {source[0].upper() + source[1:]}. ')

        if store_host:
            host_names = list({host for host in await search_engine.get_hostnames() if f'.{word}' in host})
            host_names = list(host_names)
            if source != 'hackertarget' and source != 'pentesttools' and source != 'rapiddns':
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

        if store_emails:
            email_list = await search_engine.get_emails()
            all_emails.extend(email_list)
            await db_stash.store_all(word, email_list, 'email', source)

        if store_ip:
            ips_list = await search_engine.get_ips()
            all_ip.extend(ips_list)
            await db_stash.store_all(word, all_ip, 'ip', source)

        if store_results:
            email_list, host_names, urls = await search_engine.get_results()
            all_emails.extend(email_list)
            host_names = list({host for host in host_names if f'.{word}' in host})
            all_urls.extend(urls)
            all_hosts.extend(host_names)
            await db.store_all(word, all_hosts, 'host', source)
            await db.store_all(word, all_emails, 'email', source)

        if store_people:
            people_list = await search_engine.get_people()
            all_people.extend(people_list)
            await db_stash.store_all(word, people_list, 'people', source)

        if store_links:
            links = await search_engine.get_links()
            linkedin_links_tracker.extend(links)
            if len(links) > 0:
                await db.store_all(word, links, 'linkedinlinks', engineitem)

        if store_interestingurls:
            iurls = await search_engine.get_interestingurls()
            interesting_urls.extend(iurls)
            if len(iurls) > 0:
                await db.store_all(word, iurls, 'interestingurls', engineitem)

        if store_asns:
            fasns = await search_engine.get_asns()
            total_asns.extend(fasns)
            if len(fasns) > 0:
                await db.store_all(word, fasns, 'asns', engineitem)

    stor_lst = []
    if args.source is not None:
        if args.source.lower() != 'all':
            engines = sorted(set(map(str.strip, args.source.split(','))))
        else:
            engines = Core.get_supportedengines()
        # Iterate through search engines in order
        if set(engines).issubset(Core.get_supportedengines()):
            print(f'\n[*] Target: {word} \n')

            for engineitem in engines:
                if engineitem == 'baidu':
                    try:
                        baidu_search = baidusearch.SearchBaidu(word, limit)
                        stor_lst.append(
                            store(
                                baidu_search,
                                engineitem,
                                store_host=True,
                                store_emails=True,
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
                                store_host=True,
                                store_interestingurls=True,
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
                                store_host=True,
                                store_emails=True,
                            )
                        )
                    except Exception as ex:
                        if isinstance(ex, MissingKey):
                            print(MissingKey('Bitbucket'))
                        else:
                            show_default_error_message(engineitem, word, ex)

                elif engineitem == 'brave':
                    try:
                        brave_search = bravesearch.SearchBrave(word, limit)
                        stor_lst.append(
                            store(
                                brave_search,
                                engineitem,
                                store_host=True,
                                store_emails=True,
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
                                store_host=True,
                                store_ip=True,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'builtwith':
                    try:
                        builtwith_search = builtwith.SearchBuiltWith(word)
                        stor_lst.append(store(builtwith_search, engineitem, store_host=True, store_interestingurls=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(f"Failed to perform BuiltWith search for word: '{word}'")
                            print(f'A Missing Key Error occurred in builtwith: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'censys':
                    try:
                        censys_search = censysearch.SearchCensys(word, limit)
                        stor_lst.append(
                            store(
                                censys_search,
                                engineitem,
                                store_host=True,
                                store_emails=True,
                            )
                        )
                    except MissingKey as mk:
                        if not args.quiet:
                            print(f'Censys API key is missing or invalid: {mk}')
                    except ConnectionError as ce:
                        if not args.quiet:
                            print(f'Network error while querying Censys: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            print(f'Timeout occurred while contacting Censys: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            print(f'Censys returned unexpected data: {ve}')
                    except Exception as e:
                        if not args.quiet:
                            print(f'Unexpected error occurred in Censys module: {e}')

                elif engineitem == 'certspotter':
                    try:
                        certspotter_search = certspottersearch.SearchCertspoter(word)
                        stor_lst.append(store(certspotter_search, engineitem, None, store_host=True))
                    except ConnectionError as ce:
                        if not args.quiet:
                            print(f'Network connection error while accessing Certspotter: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            print(f'Request to Certspotter timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            print(f'Certspotter returned invalid data: {ve}')
                    except MissingKey as mk:
                        if not args.quiet:
                            print(f'Unexpected response structure from Certspotter (missing key): {mk}')
                    except Exception as e:
                        if not args.quiet:
                            print(f'Unexpected error occurred in Certspotter module: {e}')

                elif engineitem == 'chaos':
                    try:
                        chaos_search = chaos.SearchChaos(word)
                        stor_lst.append(
                            store(
                                chaos_search,
                                engineitem,
                                store_host=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in Chaos: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'commoncrawl':
                    try:
                        commoncrawl_search = commoncrawl.SearchCommoncrawl(word)
                        stor_lst.append(
                            store(
                                commoncrawl_search,
                                engineitem,
                                store_host=True,
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
                                store_host=True,
                                store_ip=True,
                                store_asns=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing key error occurred in criminalip: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'crtsh':
                    try:
                        crtsh_search = crtsh.SearchCrtsh(word)
                        stor_lst.append(store(crtsh_search, 'CRTsh', store_host=True))
                    except Exception as e:
                        print(f'[!] A timeout occurred with crtsh, cannot find {args.domain}\n {e}')

                elif engineitem == 'dehashed':
                    try:
                        dehashed_search = search_dehashed.SearchDehashed(word)
                        stor_lst.append(
                            store(
                                dehashed_search,
                                engineitem,
                                store_host=False,
                                store_ip=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in dehashed: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'dnsdumpster':
                    try:
                        dnsdumpster_search = search_dnsdumpster.SearchDNSDumpster(word)
                        stor_lst.append(
                            store(
                                dnsdumpster_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                            )
                        )
                    except MissingKey as e:
                        if not args.quiet:
                            print(e)
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'duckduckgo':
                    duckduckgo_search = duckduckgosearch.SearchDuckDuckGo(word, limit)
                    stor_lst.append(
                        store(
                            duckduckgo_search,
                            engineitem,
                            store_host=True,
                            store_emails=True,
                        )
                    )

                elif engineitem == 'fofa':
                    try:
                        fofa_search = fofa.SearchFofa(word)
                        stor_lst.append(
                            store(
                                fofa_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in Fofa: {e}')
                        else:
                            show_default_error_message(engineitem, word, e)

                elif engineitem == 'fullhunt':
                    try:
                        fullhunt_search = fullhuntsearch.SearchFullHunt(word)
                        stor_lst.append(store(fullhunt_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in fullhunt: {e}')

                elif engineitem == 'github-code':
                    try:
                        github_search = githubcode.SearchGithubCode(word, limit)
                        stor_lst.append(
                            store(
                                github_search,
                                engineitem,
                                store_host=True,
                                store_emails=True,
                            )
                        )
                    except MissingKey as ex:
                        if not args.quiet:
                            print(f'A Missing Key error occurred in github-code: {ex}')

                elif engineitem == 'gitlab':
                    try:
                        gitlab_search = gitlabsearch.SearchGitlab(word)
                        stor_lst.append(
                            store(
                                gitlab_search,
                                engineitem,
                                store_host=True,
                                store_emails=True,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'hackertarget':
                    try:
                        hackertarget_search = hackertarget.SearchHackerTarget(word)
                        stor_lst.append(store(hackertarget_search, engineitem, store_host=True))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'haveibeenpwned':
                    try:
                        haveibeenpwned_search = haveibeenpwned.SearchHaveIBeenPwned(word)
                        stor_lst.append(
                            store(
                                haveibeenpwned_search,
                                engineitem,
                                store_emails=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(MissingKey('HaveIBeenPwned'))
                        else:
                            print(f'An exception has occurred in HaveIBeenPwned search: {e}')

                elif engineitem == 'hudsonrock':
                    try:
                        hudsonrock_search = hudsonrocksearch.SearchHudsonRock(word)
                        stor_lst.append(
                            store(
                                hudsonrock_search,
                                engineitem,
                                store_host=True,
                                store_emails=True,
                                store_ip=True,
                            )
                        )
                    except Exception as e:
                        print(f'An exception has occurred in Hudson Rock search: {e}')

                elif engineitem == 'hunter':
                    try:
                        hunter_search = huntersearch.SearchHunter(word, limit, start)
                        stor_lst.append(
                            store(
                                hunter_search,
                                engineitem,
                                store_host=True,
                                store_emails=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in Hunter: {e}')

                elif engineitem == 'hunterhow':
                    try:
                        hunterhow_search = searchhunterhow.SearchHunterHow(word)
                        stor_lst.append(store(hunterhow_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in Hunter How: {e}')
                        else:
                            print(f'An exception has occurred in hunterhow search: {e}')

                elif engineitem == 'intelx':
                    try:
                        intelx_search = intelxsearch.SearchIntelx(word)
                        stor_lst.append(
                            store(
                                intelx_search,
                                engineitem,
                                store_interestingurls=True,
                                store_emails=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in intelx: {e}')
                        else:
                            print(f'An exception has occurred in Intelx search: {e}')

                elif engineitem == 'leakix':
                    try:
                        leakix_search = leakix.SearchLeakix(word)
                        stor_lst.append(
                            store(
                                leakix_search,
                                engineitem,
                                store_host=True,
                                store_emails=True,
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
                                store_emails=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(f'A Missing Key error occurred in LeakLookup: {e}')
                        else:
                            print(f'An exception has occurred in LeakLookup search: {e}')

                elif engineitem == 'netlas':
                    try:
                        netlas_search = netlas.SearchNetlas(word, limit)
                        stor_lst.append(
                            store(
                                netlas_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in Netlas: {e}')

                elif engineitem == 'onyphe':
                    try:
                        onyphe_search = onyphe.SearchOnyphe(word)
                        stor_lst.append(
                            store(
                                onyphe_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                                store_asns=True,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            print(f'Network connection error while accessing Onyphe: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            print(f'Request to Onyphe timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            print(f'Onyphe returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            print(f'Unexpected response structure from Onyphe (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            print(f'Unexpected error occurred in Onyphe module: {e}')

                elif engineitem == 'otx':
                    try:
                        otxsearch_search = otxsearch.SearchOtx(word)
                        stor_lst.append(
                            store(
                                otxsearch_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            print(f'Network connection error while accessing OTX: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            print(f'Request to OTX timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            print(f'OTX returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            print(f'Unexpected response structure from OTX (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            print(f'Unexpected error occurred in OTX module: {e}')

                elif engineitem == 'pentesttools':
                    try:
                        pentesttools_search = pentesttools.SearchPentestTools(word)
                        stor_lst.append(store(pentesttools_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in PentestTools search: {e}')
                        else:
                            print(f'An exception has occurred in PentestTools search: {e}')

                elif engineitem == 'projectdiscovery':
                    try:
                        projectdiscovery_search = projectdiscovery.SearchDiscovery(word)
                        stor_lst.append(store(projectdiscovery_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in ProjectDiscovery: {e}')
                        else:
                            print('An exception has occurred in ProjectDiscovery')

                elif engineitem == 'rapiddns':
                    try:
                        rapiddns_search = rapiddns.SearchRapidDns(word)
                        stor_lst.append(store(rapiddns_search, engineitem, store_host=True))
                    except ConnectionError as ce:
                        if not args.quiet:
                            print(f'Network connection error while accessing RapidDNS: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            print(f'Request to RapidDNS timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            print(f'RapidDNS returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            print(f'Unexpected response structure from RapidDNS (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            print(f'Unexpected error occurred in RapidDNS module: {e}')

                elif engineitem == 'robtex':
                    try:
                        robtex_search = robtex.SearchRobtex(word)
                        stor_lst.append(
                            store(
                                robtex_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'rocketreach':
                    try:
                        rocketreach_search = rocketreach.SearchRocketReach(word, limit)
                        stor_lst.append(store(rocketreach_search, engineitem, store_links=True, store_emails=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in RocketReach: {e}')
                        else:
                            print(f'An exception has occurred in RocketReach: {e}')

                elif engineitem == 'securityscorecard':
                    try:
                        securityscorecard_search = securityscorecard.SearchSecurityScorecard(word)
                        stor_lst.append(
                            store(
                                securityscorecard_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                                store_interestingurls=True,
                                store_asns=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(MissingKey('SecurityScorecard'))
                        else:
                            print(f'An exception has occurred in SecurityScorecard search: {e}')

                elif engineitem == 'securityTrails':
                    try:
                        securitytrails_search = securitytrailssearch.SearchSecuritytrail(word)
                        stor_lst.append(
                            store(
                                securitytrails_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred Security Trails: {e}')

                elif engineitem == 'shodan':
                    try:
                        shodan_search = shodansearch.SearchShodan()

                        # For normal module usage, we need to create a wrapper that works with the store function
                        class ShodanWrapper:
                            def __init__(self, domain):
                                self.word = domain
                                self.hosts = set()
                                self.shodan = shodan_search

                            async def do_search(self):
                                import socket

                                try:
                                    # Resolve domain to IP and search in Shodan
                                    ip = socket.gethostbyname(self.word)
                                    print(f'\tSearching Shodan for {ip}')
                                    result = await self.shodan.search_ip(ip)
                                    if ip in result and isinstance(result[ip], dict):
                                        # Add the IP as a host for consistency with other modules
                                        self.hosts.add(ip)
                                        print(f'Found Shodan data for {ip}')
                                    elif ip in result and isinstance(result[ip], str):
                                        print(f'{ip}: {result[ip]}')
                                except Exception as e:
                                    print(f'Error in Shodan search: {e}')

                            def get_hostnames(self):
                                return list(self.hosts)

                        shodan_wrapper = ShodanWrapper(word)
                        stor_lst.append(store(shodan_wrapper, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in Shodan search: {e}')
                        else:
                            print(f'An exception has occurred in Shodan search: {e}')

                elif engineitem == 'subdomaincenter':
                    try:
                        subdomaincenter_search = subdomaincenter.SubdomainCenter(word)
                        stor_lst.append(store(subdomaincenter_search, engineitem, store_host=True))
                    except ConnectionError as ce:
                        if not args.quiet:
                            print(f'Network connection error while accessing SubdomainCenter: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            print(f'Request to SubdomainCenter timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            print(f'SubdomainCenter returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            print(f'Unexpected response structure from SubdomainCenter (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            print(f'Unexpected error occurred in SubdomainCenter module: {e}')

                elif engineitem == 'subdomainfinderc99':
                    try:
                        subdomainfinderc99_search = subdomainfinderc99.SearchSubdomainfinderc99(word)
                        stor_lst.append(store(subdomainfinderc99_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in Subdomainfinderc99 search: {e}')
                        else:
                            print(f'An exception has occurred in Subdomainfinderc99 search: {e}')

                elif engineitem == 'thc':
                    try:
                        thc_search = thc.SearchThc(word)
                        stor_lst.append(store(thc_search, engineitem, store_host=True))
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'threatcrowd':
                    try:
                        threatcrowd_search = threatcrowd.SearchThreatcrowd(word)
                        stor_lst.append(
                            store(
                                threatcrowd_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
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
                                store_host=True,
                                store_emails=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in Tomba: {e}')

                elif engineitem == 'urlscan':
                    try:
                        urlscan_search = urlscan.SearchUrlscan(word)
                        stor_lst.append(
                            store(
                                urlscan_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                                store_interestingurls=True,
                                store_asns=True,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            print(f'Network connection error while accessing Urlscan: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            print(f'Request to Urlscan timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            print(f'Urlscan returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            print(f'Unexpected response structure from Urlscan (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            print(f'Unexpected error occurred in Urlscan module: {e}')

                elif engineitem == 'venacus':
                    try:
                        venacus_search = venacussearch.SearchVenacus(word=word, limit=limit, offset_doc=start)
                        stor_lst.append(
                            store(
                                venacus_search,
                                engineitem,
                                store_emails=True,
                                store_ip=True,
                                store_people=True,
                                store_interestingurls=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in venacus search: {e}')
                        else:
                            print(f'An exception has occurred in venacus search: {e}')

                elif engineitem == 'virustotal':
                    try:
                        virustotal_search = virustotal.SearchVirustotal(word)
                        stor_lst.append(store(virustotal_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in virustotal search: {e}')

                elif engineitem == 'waybackarchive':
                    try:
                        waybackarchive_search = waybackarchive.SearchWaybackarchive(word)
                        stor_lst.append(
                            store(
                                waybackarchive_search,
                                engineitem,
                                store_host=True,
                            )
                        )
                    except Exception as e:
                        show_default_error_message(engineitem, word, e)

                elif engineitem == 'whoisxml':
                    try:
                        whoisxml_search = whoisxml.SearchWhoisXML(word)
                        stor_lst.append(store(whoisxml_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in whoisxml search: {e}')
                        else:
                            print(f'An exception has occurred in WhoisXML search: {e}')

                elif engineitem == 'windvane':
                    try:
                        windvane_search = windvane.SearchWindvane(word)
                        stor_lst.append(
                            store(
                                windvane_search,
                                engineitem,
                                store_host=True,
                                store_ip=True,
                                store_emails=True,
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
                                store_host=True,
                                store_emails=True,
                            )
                        )
                    except ConnectionError as ce:
                        if not args.quiet:
                            print(f'Network connection error while accessing Yahoo: {ce}')
                    except TimeoutError as te:
                        if not args.quiet:
                            print(f'Request to Yahoo timed out: {te}')
                    except ValueError as ve:
                        if not args.quiet:
                            print(f'Yahoo returned invalid or unexpected data: {ve}')
                    except KeyError as ke:
                        if not args.quiet:
                            print(f'Unexpected response structure from Yahoo (missing key): {ke}')
                    except Exception as e:
                        if not args.quiet:
                            print(f'Unexpected error occurred in Yahoo module: {e}')

                elif engineitem == 'zoomeye':
                    try:
                        zoomeye_search = zoomeyesearch.SearchZoomEye(word, limit)
                        stor_lst.append(
                            store(
                                zoomeye_search,
                                engineitem,
                                store_host=True,
                                store_emails=True,
                                store_ip=True,
                                store_interestingurls=True,
                                store_asns=True,
                            )
                        )
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            if not args.quiet:
                                print(f'A Missing Key error occurred in zoomeye: {e}')

        elif rest_args is not None:
            try:
                rest_args.dns_brute
            except Exception:
                print('\n[!] Invalid source.\n')
                sys.exit(1)
        else:
            # Print which engines aren't supported
            unsupported_engines = set(engines) - set(Core.get_supportedengines())
            if unsupported_engines:
                print(f'The following engines are not supported: {unsupported_engines}')
            print('\n[!] Invalid source.\n')
            sys.exit(1)

    async def worker(queue):
        while True:
            # Get a "work item" out of the queue.
            stor = await queue.get()
            try:
                await stor
                queue.task_done()
                # Notify the queue that the "work item" has been processed.
            except Exception:
                print('\n A error occurred while processing a "work item".\n')
                queue.task_done()

    async def handler(lst):
        queue: asyncio.Queue[Awaitable[Any]] = asyncio.Queue()
        for stor_method in lst:
            # enqueue the coroutines
            queue.put_nowait(stor_method)
        # Create three worker tasks to process the queue concurrently.
        tasks = []
        for i in range(3):
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
    return_ips: list = []
    if rest_args is not None and len(rest_filename) == 0 and rest_args.dns_brute is False:
        # Indicates user is using REST api but not wanting output to be saved to a file
        # cast to string so Rest API can understand the type
        return_ips.extend([str(ip) for ip in sorted([netaddr.IPAddress(ip.strip()) for ip in set(all_ip)])])
        # return list(set(all_emails)), return_ips, full, '', ''
        all_hosts = [host.replace('www.', '') for host in all_hosts if host.replace('www.', '') in all_hosts]
        all_hosts = list(sorted(set(all_hosts)))
        return (
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
    # Check to see if all_emails and all_hosts are defined.
    try:
        all_emails
    except NameError:
        print('\n\n[!] No emails found because all_emails is not defined.\n\n ')
        sys.exit(1)
    try:
        all_hosts
    except NameError:
        print('\n\n[!] No hosts found because all_hosts is not defined.\n\n ')
        sys.exit(1)

    # Results
    if len(total_asns) > 0:
        print_section(f'\n[*] ASNS found: {len(total_asns)}', total_asns, '--------------------')
        total_asns = sorted_unique(total_asns)

    if len(interesting_urls) > 0:
        print_section(f'\n[*] Interesting Urls found: {len(interesting_urls)}', interesting_urls, '--------------------')
        interesting_urls = sorted_unique(interesting_urls)

    if len(twitter_people_list_tracker) == 0 and 'twitter' in engines:
        print('\n[*] No Twitter users found.\n\n')
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
            print('\n[*] No Trello URLs found.')
    else:
        total = length_urls
        print_section('\n[*] Trello URLs found: ' + str(total), all_urls, '--------------------')
        all_urls = sorted_unique(all_urls)

    if len(all_ip) == 0:
        print('\n[*] No IPs found.')
    else:
        print('\n[*] IPs found: ' + str(len(all_ip)))
        print('-------------------')
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
            except Exception as e:
                print(f'An exception has occurred while adding: {ip} to ip_list: {e}')
                continue
        ip_list = list(sorted(ip_list))
        print('\n'.join(map(str, ip_list)))
        # Populate host_ip from ip_list for DNS lookup, virtual hosts search, and Shodan search
        host_ip = ip_list

    if len(all_emails) == 0:
        print('\n[*] No emails found.')
    else:
        print('\n[*] Emails found: ' + str(len(all_emails)))
        print('----------------------')
        all_emails = sorted(list(set(all_emails)))
        print('\n'.join(all_emails))

    if len(all_people) == 0:
        print('\n[*] No people found.')
    else:
        print('\n[*] People found: ' + str(len(all_people)))
        print('----------------------')
        for person in all_people:
            print(person)

    if len(all_hosts) == 0:
        print('\n[*] No hosts found.\n\n')
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
                    if host[:4] == 'www.':
                        if host[4:] in all_hosts or host[4:] in full:
                            temp.add(host[4:])
                            continue
                    temp.add(host)
            full = list(sorted(temp))
            full.sort(key=lambda el: el.split(':')[0])
            print('\n[*] Hosts found: ' + str(len(full)))
            print('---------------------')
            for host in full:
                print(host)
                try:
                    if ':' in host:
                        _, addr = host.split(':', 1)
                        await db.store(word, addr, 'ip', 'DNS-resolver')
                except Exception as e:
                    print(f'An exception has occurred while attempting to insert: {host} IP into DB: {e}')
                    continue
        else:
            all_hosts = [host.replace('www.', '') for host in all_hosts if host.replace('www.', '') in all_hosts]
            all_hosts = list(sorted(set(all_hosts)))
            print('\n[*] Hosts found: ' + str(len(all_hosts)))
            print('---------------------')
            for host in all_hosts:
                print(host)

    # DNS brute force
    if dnsbrute and dnsbrute[0] is True:
        print('\n[*] Starting DNS brute force.')
        dns_force = dnssearch.DnsForce(word, final_dns_resolver_list, verbose=True)
        resolved_pair, hosts, ips = await dns_force.run()
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
                if host[:4] == 'www.':
                    if host[4:] in all_hosts or host[4:] in full:
                        continue
                if host not in full:
                    full.append(host)
                    temp.add(host)
                if host not in all_hosts:
                    all_hosts.append(host)
        print('\n[*] Hosts found after DNS brute force:')
        for sub in temp:
            print(sub)
        await db.store_all(word, list(sorted(temp)), 'host', 'dns_bruteforce')

    takeover_results = dict()
    # TakeOver Checking
    if takeover_status:
        print('\n[*] Performing subdomain takeover check')
        print('\n[*] Subdomain Takeover checking IS ACTIVE RECON')
        search_take = takeover.TakeOver(all_hosts)
        await search_take.populate_fingerprints()
        await search_take.process(proxy=use_proxy)
        takeover_results = await search_take.get_takeover_results()
    # DNS reverse lookup
    dnsrev: list = []
    # print(f'DNSlookup: {dnslookup}')
    if dnslookup is True:
        print('\n[*] Starting active queries for DNSLookup.')

        # reverse each iprange in a separate task
        __reverse_dns_tasks: dict = {}
        for entry in host_ip:
            __ip_range = dnssearch.serialize_ip_range(ip=entry, netmask='24')
            if __ip_range and __ip_range not in set(__reverse_dns_tasks.keys()):
                print('\n[*] Performing reverse lookup on ' + __ip_range)
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
        print('\n[*] Hosts found after reverse lookup (in target domain):')
        print('--------------------------------------------------------')
        for xh in dnsrev:
            print(xh)

    # Screenshots
    screenshot_tups = []
    if len(args.screenshot) > 0:
        screen_shotter = ScreenShotter(args.screenshot)
        path_exists = screen_shotter.verify_path()
        # Verify the path exists, if not create it or if user does not create it skips screenshot
        if path_exists:
            await screen_shotter.verify_installation()
            print(f'\nScreenshots can be found in: {screen_shotter.output}{screen_shotter.slash}')
            start_time = time.perf_counter()
            print('Filtering domains for ones we can reach')
            if dnsresolve is None or len(final_dns_resolver_list) > 0:
                unique_resolved_domains = {url.split(':')[0] for url in full if ':' in url and 'www.' not in url}
            else:
                # Technically not resolved in this case, which is not ideal
                # You should always use dns resolve when doing screenshotting
                print('NOTE for future use cases you should only use screenshotting in tandem with DNS resolving')
                unique_resolved_domains = set(all_hosts)
            if len(unique_resolved_domains) > 0:
                # First filter out ones that didn't resolve
                print('Attempting to visit unique resolved domains, this is ACTIVE RECON')
                async with Pool(10) as pool:
                    results = await pool.map(screen_shotter.visit, list(unique_resolved_domains))
                    # Filter out domains that we couldn't connect to
                    unique_resolved_domains_list = list(sorted({tup[0] for tup in results if len(tup[1]) > 0}))
                async with Pool(3) as pool:
                    print(f'Length of unique resolved domains: {len(unique_resolved_domains_list)} chunking now!\n')
                    # If you have the resources, you could make the function faster by increasing the chunk number
                    chunk_number = 14
                    for chunk in screen_shotter.chunk_list(unique_resolved_domains_list, chunk_number):
                        try:
                            screenshot_tups.extend(await pool.map(screen_shotter.take_screenshot, chunk))
                        except Exception as ee:
                            print(f'An exception has occurred while mapping: {ee}')
            end = time.perf_counter()
            # There is probably an easier way to do this
            total = int(end - start_time)
            mon, sec = divmod(total, 60)
            hr, mon = divmod(mon, 60)
            total_time = f'{mon:02d}:{sec:02d}'
            print(f'Finished taking screenshots in {total_time} seconds')
            print('[+] Note there may be leftover chrome processes you may have to kill manually\n')

    # Shodan
    shodanres = []
    if shodan is True:
        print('[*] Searching Shodan. ')
        try:
            for ip in host_ip:
                try:
                    print('\tSearching for ' + ip)
                    shodan_search = shodansearch.SearchShodan()
                    shodandict = await shodan_search.search_ip(ip)
                    await asyncio.sleep(5)

                    # Check if the result is a string (error message)
                    if isinstance(shodandict[ip], str):
                        print(f'{ip}: {shodandict[ip]}')
                        continue

                    # Process the results if it's a dictionary
                    if isinstance(shodandict[ip], dict):
                        rowdata = []
                        for key, value in shodandict[ip].items():
                            if isinstance(value, int):
                                value = str(value)
                            if isinstance(value, list):
                                value = ', '.join(map(str, value))
                            rowdata.append(value)
                        shodanres.append(rowdata)
                        print(ujson.dumps(shodandict[ip], indent=4, sort_keys=True))
                        print('\n')
                except Exception as ip_error:
                    print(f'[SHODAN-error] Error searching {ip}: {ip_error}')
                    continue
        except Exception as e:
            print(f'[!] An error occurred with Shodan: {e} ')
    else:
        pass

    if filename != '':
        print('\n[*] Reporting started.')
        try:
            if len(rest_filename) == 0:
                filename = filename.rsplit('.', 1)[0] + '.xml'
            else:
                filename = 'theHarvester/app/static/' + rest_filename.rsplit('.', 1)[0] + '.xml'
            # TODO use aiofiles if user is using rest api
            # XML REPORT SECTION
            with open(filename, 'w+') as file:
                file.write('<?xml version="1.0" encoding="UTF-8"?><theHarvester>')
                sanitized_args = [sanitize_for_xml(f'"{arg}"' if ' ' in arg else arg) for arg in sys.argv[1:]]
                file.write('<cmd>' + ' '.join(sanitized_args) + '</cmd>')
                for x in all_emails:
                    file.write('<email>' + sanitize_for_xml(x) + '</email>')
                for x in full:
                    host, ip = x.split(':', 1) if ':' in x else (x, '')
                    if ip and len(ip) > 3:
                        file.write(f'<host><ip>{sanitize_for_xml(ip)}</ip><hostname>{sanitize_for_xml(host)}</hostname></host>')
                    else:
                        file.write(f'<host>{sanitize_for_xml(host)}</host>')
                for x in vhost:
                    host, ip = x.split(':', 1) if ':' in x else (x, '')
                    if ip and len(ip) > 3:
                        file.write(
                            f'<vhost><ip>{sanitize_for_xml(ip)} </ip><hostname>{sanitize_for_xml(host)}</hostname></vhost>'
                        )
                    else:
                        file.write(f'<vhost>{sanitize_for_xml(host)}</vhost>')
                # TODO add Shodan output into XML report
                file.write('</theHarvester>')
                print('[*] XML File saved.')
        except Exception as error:
            print(f'[!] An error occurred while saving the XML file: {error}')

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
            with open(filename, 'w+') as fp:
                dumped_json = ujson.dumps(json_dict, sort_keys=True)
                fp.write(dumped_json)
            print('[*] JSON File saved.')
        except Exception as er:
            print(f'[!] An error occurred while saving the JSON file: {er} ')
        print('\n\n')

    # Enhanced code block for API Endpoint scanning feature
    if args.api_scan or 'api_endpoints' in engines:
        try:
            # Define a default wordlist if none is specified
            wordlist = args.wordlist if args.wordlist else str(DATA_DIR / 'wordlists' / 'api_endpoints.txt')

            # Check if the wordlist file exists first
            if not os.path.exists(wordlist):
                print(f'\n[!] Wordlist not found: {wordlist}')
                print('Creating a basic API wordlist for scanning...')
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
                with open(temp_wordlist, 'w') as f:
                    f.write('\n'.join(basic_endpoints))
                wordlist = temp_wordlist
                print(f'Basic API wordlist created with {len(basic_endpoints)} endpoints.')

            print(f'\n[*] Starting API endpoint scanning with wordlist: {wordlist}')
            api_scanner = api_endpoints.SearchApiEndpoints(word=args.domain, wordlist=wordlist)
            await api_scanner.do_search()

            # Print results
            endpoints_found = api_scanner.get_found_endpoints()
            print(f'\n[*] API Endpoints found: {len(endpoints_found)}')
            for endpoint in endpoints_found:
                print(f'    - {endpoint}')

            interesting_endpoints = api_scanner.get_interesting_endpoints()
            print(f'\n[*] Interesting endpoints (200, 201, 202): {len(interesting_endpoints)}')
            for endpoint in interesting_endpoints:
                print(f'    - {endpoint}')

            auth_required = api_scanner.get_auth_required()
            print(f'\n[*] Endpoints requiring authentication: {len(auth_required)}')
            for endpoint in auth_required:
                print(f'    - {endpoint}')

            api_versions = api_scanner.get_api_versions()
            print(f'\n[*] Detected API versions: {len(api_versions)}')
            for version in api_versions:
                print(f'    - {version}')

            rate_limits = api_scanner.get_rate_limits()
            print(f'\n[*] Rate limited endpoints: {len(rate_limits)}')
            for endpoint, info in rate_limits.items():
                print(f'    - {endpoint} ({info.method})')

            methods = api_scanner.get_methods()
            print(f'\n[*] HTTP methods used: {", ".join(methods)}')

            status_codes = api_scanner.get_status_codes()
            print(f'\n[*] HTTP status codes encountered: {", ".join(map(str, status_codes))}')

            # Add results to storage
            db = stash.StashManager()
            await db.store_all(word, endpoints_found, 'api_endpoint', 'api_scan')

            # Use custom database function if available
            try:
                # Try to use the storage module if available
                db_storage = stash.StashManager()
                await db_storage.store_all(word, endpoints_found, 'api_endpoint', 'api_scan')
            except AttributeError:
                print('\n[*] No custom database functions found')

            # Add to interesting URLs if any endpoints were found
            if interesting_endpoints:
                new_urls = [f'https://{args.domain}{endpoint}' for endpoint in interesting_endpoints]
                interesting_urls.extend(new_urls)

                # Also add complete domain paths to the interesting_urls list
                all_urls.extend(new_urls)

            print('\n[+] API scanning completed successfully.')

        except MissingKey:
            print('\n[!] API endpoint scanning requires a wordlist. Use -w to specify a wordlist file.')
            print('    Creating a basic wordlist and trying again...')
            # The wordlist creation code above could be used here
        except Exception as e:
            print(f'\n[!] An exception has occurred in API Endpoints scanning: {e}')
            print('    Continuing with the rest of the scan...')
            traceback.print_exc()  # More detailed error information for developers

    if 'securityscorecard' in engines:
        try:
            print('\n[*] Performing SecurityScorecard scan...')
            securityscorecard_scanner = securityscorecard.SearchSecurityScorecard(word)
            await securityscorecard_scanner.process(use_proxy)

            # Use the existing API to get results
            hosts = await securityscorecard_scanner.get_hostnames()
            if hosts:
                print(f'\n[*] SecurityScorecard results: {len(hosts)} hosts found')
                for host in hosts:
                    print(f'    - {host}')

                all_hosts.extend(hosts)

            ips = await securityscorecard_scanner.get_ips()
            if ips:
                print(f'\n[*] SecurityScorecard IPs found: {len(ips)}')
                for ip in ips:
                    print(f'    - {ip}')
                all_ip.extend(ips)

        except Exception as e:
            print(f'An exception has occurred in SecurityScorecard scanning: {e}')

    if 'builtwith' in engines:
        try:
            print('\n[*] Performing BuiltWith scan...')
            builtwith_scanner = builtwith.SearchBuiltWith(word)
            await builtwith_scanner.process(use_proxy)

            hosts = await builtwith_scanner.get_hostnames()
            if hosts:
                print(f'\n[*] BuiltWith results: {len(hosts)} hosts found')
                for host in hosts:
                    print(f'    - {host}')

                # Add results to the main host list
                all_hosts.extend(hosts)

            urls = list(await builtwith_scanner.get_interesting_urls())
            if urls:
                print(f'\n[*] BuiltWith interesting URLs found: {len(urls)}')
                for url in urls:
                    print(f'    - {url}')
                interesting_urls.extend(urls)

        except Exception as e:
            if isinstance(e, MissingKey):
                if not args.quiet:
                    print(MissingKey('BuiltWith'))
                else:
                    print(f'An exception has occurred in BuiltWith scanning: {e}')

    sys.exit(0)


async def entry_point() -> None:
    try:
        Core.banner()
        await start()
    except KeyboardInterrupt:
        print('\n\n[!] ctrl+c detected from user, quitting.\n\n ')
    except Exception as error_entry_point:
        print(error_entry_point)
        sys.exit(1)
