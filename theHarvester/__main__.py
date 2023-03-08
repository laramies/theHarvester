#!/usr/bin/env python3
from typing import Optional, Dict, List
from theHarvester.discovery import *
from theHarvester.discovery import dnssearch, takeover, shodansearch
from theHarvester.discovery.constants import *
from theHarvester.lib import hostchecker
from theHarvester.lib import stash
from theHarvester.lib.core import *
import argparse
import asyncio
import ujson
import netaddr
import re
import sys
import string
import secrets


async def start(rest_args: Optional[argparse.Namespace] = None):
    """Main program function"""
    parser = argparse.ArgumentParser(description='theHarvester is used to gather open source intelligence (OSINT) on a company or domain.')
    parser.add_argument('-d', '--domain', help='Company name or domain to search.', required=True)
    parser.add_argument('-l', '--limit', help='Limit the number of search results, default=500.', default=500, type=int)
    parser.add_argument('-S', '--start', help='Start with result number X, default=0.', default=0, type=int)
    parser.add_argument('-p', '--proxies', help='Use proxies for requests, enter proxies in proxies.yaml.', default=False, action='store_true')
    parser.add_argument('-s', '--shodan', help='Use Shodan to query discovered hosts.', default=False, action='store_true')
    parser.add_argument('--screenshot', help='Take screenshots of resolved domains specify output directory: --screenshot output_directory', default="", type=str)
    parser.add_argument('-v', '--virtual-host', help='Verify host name via DNS resolution and search for virtual hosts.', action='store_const', const='basic', default=False)
    parser.add_argument('-e', '--dns-server', help='DNS server to use for lookup.')
    parser.add_argument('-r', '--take-over', help='Check for takeovers.', default=False, action='store_true')
    parser.add_argument('-n', '--dns-lookup', help='Enable DNS server lookup, default False.', default=False, action='store_true')
    parser.add_argument('-c', '--dns-brute', help='Perform a DNS brute force on the domain.', default=False, action='store_true')
    parser.add_argument('-f', '--filename', help='Save the results to an XML and JSON file.', default='', type=str)
    parser.add_argument('-b', '--source', help='''anubis, baidu, bevigil, binaryedge, bing, bingapi, bufferoverun, censys, certspotter, crtsh,
                            dnsdumpster, duckduckgo, fullhunt, github-code, hackertarget, hunter, intelx,
                            otx, pentesttools, projectdiscovery,
                            qwant, rapiddns, rocketreach, securityTrails, sublist3r, threatcrowd, threatminer,
                            urlscan, virustotal, yahoo, zoomeye''')

    # determines if filename is coming from rest api or user
    rest_filename = ''
    # indicates this from the rest API
    if rest_args:
        if rest_args.source and rest_args.source == "getsources":
            return list(sorted(Core.get_supportedengines()))
        elif rest_args.dns_brute:
            args = rest_args
            dnsbrute = (rest_args.dns_brute, True)
        else:
            args = rest_args
            # We need to make sure the filename is random as to not overwrite other files
            filename: str = args.filename
            alphabet = string.ascii_letters + string.digits
            rest_filename += f"{''.join(secrets.choice(alphabet) for _ in range(32))}_{filename}" \
                if len(filename) != 0 else ""
    else:
        args = parser.parse_args()
        filename = args.filename
        dnsbrute = (args.dns_brute, False)
    try:
        db = stash.StashManager()
        await db.do_init()
    except Exception:
        pass
    import os
    if len(filename) > 2 and filename[:2] == "~/":
        filename = os.path.expanduser(filename)
    all_emails: List = []
    all_hosts: List = []
    all_ip: List = []
    dnslookup = args.dns_lookup
    dnsserver = args.dns_server
    engines: List = []
    # If the user specifies

    full: List = []
    ips: List = []
    host_ip: List = []
    limit: int = args.limit
    shodan = args.shodan
    start: int = args.start
    all_urls: list = []
    vhost: list = []
    virtual = args.virtual_host
    word: str = args.domain.rstrip('\n')
    takeover_status = args.take_over
    use_proxy = args.proxies
    linkedin_people_list_tracker: List = []
    linkedin_links_tracker: List = []
    twitter_people_list_tracker: List = []
    interesting_urls: list = []
    total_asns: list = []

    linkedin_people_list_tracker = []
    linkedin_links_tracker = []
    twitter_people_list_tracker = []

    interesting_urls = []
    total_asns = []

    async def store(search_engine: Any, source: str, process_param: Any = None, store_host: bool = False,
                    store_emails: bool = False, store_ip: bool = False, store_people: bool = False,
                    store_links: bool = False, store_results: bool = False,
                    store_interestingurls: bool = False, store_asns: bool = False) -> None:
        """
        Persist details into the database.
        The details to be stored is controlled by the parameters passed to the method.

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
        await search_engine.process(use_proxy) if process_param is None else await \
            search_engine.process(process_param, use_proxy)
        db_stash = stash.StashManager()
        if source:
            print(f'\033[94m[*] Searching {source[0].upper() + source[1:]}. ')
        if store_host:
            host_names = [host for host in filter(await search_engine.get_hostnames()) if f'.{word}' in host]
            if source != 'hackertarget' and source != 'pentesttools' and source != 'rapiddns':
                # If source is inside this conditional it means the hosts returned must be resolved to obtain ip
                full_hosts_checker = hostchecker.Checker(host_names)
                temp_hosts, temp_ips = await full_hosts_checker.check()
                ips.extend(temp_ips)
                full.extend(temp_hosts)
            else:
                full.extend(host_names)
            all_hosts.extend(host_names)
            await db_stash.store_all(word, all_hosts, 'host', source)
        if store_emails:
            email_list = filter(await search_engine.get_emails())
            all_emails.extend(email_list)
            await db_stash.store_all(word, email_list, 'email', source)
        if store_ip:
            ips_list = await search_engine.get_ips()
            all_ip.extend(ips_list)
            await db_stash.store_all(word, all_ip, 'ip', source)
        if store_results:
            email_list, host_names, urls = await search_engine.get_results()
            all_emails.extend(email_list)
            host_names = [host for host in filter(host_names) if f'.{word}' in host]
            all_urls.extend(filter(urls))
            all_hosts.extend(host_names)
            await db.store_all(word, all_hosts, 'host', source)
            await db.store_all(word, all_emails, 'email', source)
        if store_people:
            people_list = await search_engine.get_people()
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
                if engineitem == 'anubis':
                    from theHarvester.discovery import anubis
                    try:
                        anubis_search = anubis.SearchAnubis(word)
                        stor_lst.append(store(anubis_search, engineitem, store_host=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'baidu':
                    from theHarvester.discovery import baidusearch
                    try:
                        baidu_search = baidusearch.SearchBaidu(word, limit)
                        stor_lst.append(store(baidu_search, engineitem, store_host=True, store_emails=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'bevigil':
                    from theHarvester.discovery import bevigil
                    try:
                        bevigil_search = bevigil.SearchBeVigil(word)
                        stor_lst.append(store(bevigil_search, engineitem, store_host=True, store_interestingurls=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'binaryedge':
                    from theHarvester.discovery import binaryedgesearch
                    try:
                        binaryedge_search = binaryedgesearch.SearchBinaryEdge(word, limit)
                        stor_lst.append(store(binaryedge_search, engineitem, store_host=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'bing' or engineitem == 'bingapi':
                    from theHarvester.discovery import bingsearch
                    try:
                        bing_search = bingsearch.SearchBing(word, limit, start)
                        bingapi = ''
                        if engineitem == 'bingapi':
                            bingapi += 'yes'
                        else:
                            bingapi += 'no'
                        stor_lst.append(
                            store(bing_search, 'bing', process_param=bingapi, store_host=True, store_emails=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            print(e)

                elif engineitem == 'bufferoverun':
                    from theHarvester.discovery import bufferoverun
                    try:
                        bufferoverun_search = bufferoverun.SearchBufferover(word)
                        stor_lst.append(store(bufferoverun_search, engineitem, store_host=True, store_ip=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'censys':
                    from theHarvester.discovery import censysearch
                    try:
                        censys_search = censysearch.SearchCensys(word, limit)
                        stor_lst.append(store(censys_search, engineitem, store_host=True, store_emails=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)

                elif engineitem == 'certspotter':
                    from theHarvester.discovery import certspottersearch
                    try:
                        certspotter_search = certspottersearch.SearchCertspoter(word)
                        stor_lst.append(store(certspotter_search, engineitem, None, store_host=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'crtsh':
                    try:
                        from theHarvester.discovery import crtsh
                        crtsh_search = crtsh.SearchCrtsh(word)
                        stor_lst.append(store(crtsh_search, 'CRTsh', store_host=True))
                    except Exception as e:
                        print(f'[!] A timeout occurred with crtsh, cannot find {args.domain}\n {e}')

                elif engineitem == 'dnsdumpster':
                    try:
                        from theHarvester.discovery import dnsdumpster
                        dns_dumpster_search = dnsdumpster.SearchDnsDumpster(word)
                        stor_lst.append(store(dns_dumpster_search, engineitem, store_host=True, store_ip=True))
                    except Exception as e:
                        print(f'[!] An error occurred with dnsdumpster: {e}')

                elif engineitem == 'duckduckgo':
                    from theHarvester.discovery import duckduckgosearch
                    duckduckgo_search = duckduckgosearch.SearchDuckDuckGo(word, limit)
                    stor_lst.append(store(duckduckgo_search, engineitem, store_host=True, store_emails=True))

                elif engineitem == 'fullhunt':
                    from theHarvester.discovery import fullhuntsearch
                    try:
                        fullhunt_search = fullhuntsearch.SearchFullHunt(word)
                        stor_lst.append(store(fullhunt_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)

                elif engineitem == 'github-code':
                    try:
                        from theHarvester.discovery import githubcode
                        github_search = githubcode.SearchGithubCode(word, limit)
                        stor_lst.append(store(github_search, engineitem, store_host=True, store_emails=True))
                    except MissingKey as ex:
                        print(ex)

                elif engineitem == 'hackertarget':
                    from theHarvester.discovery import hackertarget
                    hackertarget_search = hackertarget.SearchHackerTarget(word)
                    stor_lst.append(store(hackertarget_search, engineitem, store_host=True))

                elif engineitem == 'hunter':
                    from theHarvester.discovery import huntersearch
                    # Import locally or won't work.
                    try:
                        hunter_search = huntersearch.SearchHunter(word, limit, start)
                        stor_lst.append(store(hunter_search, engineitem, store_host=True, store_emails=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)

                elif engineitem == 'intelx':
                    from theHarvester.discovery import intelxsearch
                    # Import locally or won't work.
                    try:
                        intelx_search = intelxsearch.SearchIntelx(word)
                        stor_lst.append(store(intelx_search, engineitem, store_interestingurls=True, store_emails=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            print(f'An exception has occurred in Intelx search: {e}')

                elif engineitem == 'otx':
                    from theHarvester.discovery import otxsearch
                    try:
                        otxsearch_search = otxsearch.SearchOtx(word)
                        stor_lst.append(store(otxsearch_search, engineitem, store_host=True, store_ip=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'pentesttools':
                    from theHarvester.discovery import pentesttools
                    try:
                        pentesttools_search = pentesttools.SearchPentestTools(word)
                        stor_lst.append(store(pentesttools_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            print(f'An exception has occurred in PentestTools search: {e}')

                elif engineitem == 'projectdiscovery':
                    from theHarvester.discovery import projectdiscovery
                    try:
                        projectdiscovery_search = projectdiscovery.SearchDiscovery(word)
                        stor_lst.append(store(projectdiscovery_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            print('An exception has occurred in ProjectDiscovery')

                elif engineitem == 'qwant':
                    from theHarvester.discovery import qwantsearch
                    qwant_search = qwantsearch.SearchQwant(word, start, limit)
                    stor_lst.append(store(qwant_search, engineitem, store_host=True, store_emails=True))

                elif engineitem == 'rapiddns':
                    from theHarvester.discovery import rapiddns
                    try:
                        rapiddns_search = rapiddns.SearchRapidDns(word)
                        stor_lst.append(store(rapiddns_search, engineitem, store_host=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'rocketreach':
                    from theHarvester.discovery import rocketreach
                    try:
                        rocketreach_search = rocketreach.SearchRocketReach(word, limit)
                        stor_lst.append(store(rocketreach_search, engineitem, store_links=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            print(f'An exception has occurred in RocketReach: {e}')

                elif engineitem == 'securityTrails':
                    from theHarvester.discovery import securitytrailssearch
                    try:
                        securitytrails_search = securitytrailssearch.SearchSecuritytrail(word)
                        stor_lst.append(store(securitytrails_search, engineitem, store_host=True, store_ip=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)

                elif engineitem == 'sublist3r':
                    from theHarvester.discovery import sublist3r
                    try:
                        sublist3r_search = sublist3r.SearchSublist3r(word)
                        stor_lst.append(store(sublist3r_search, engineitem, store_host=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'threatcrowd':
                    from theHarvester.discovery import threatcrowd
                    try:
                        threatcrowd_search = threatcrowd.SearchThreatcrowd(word)
                        stor_lst.append(store(threatcrowd_search, engineitem, store_host=True, store_ip=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'threatminer':
                    from theHarvester.discovery import threatminer
                    try:
                        threatminer_search = threatminer.SearchThreatminer(word)
                        stor_lst.append(store(threatminer_search, engineitem, store_host=True, store_ip=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'urlscan':
                    from theHarvester.discovery import urlscan
                    try:
                        urlscan_search = urlscan.SearchUrlscan(word)
                        stor_lst.append(store(urlscan_search, engineitem, store_host=True, store_ip=True,
                                              store_interestingurls=True, store_asns=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'virustotal':
                    try:
                        from theHarvester.discovery import virustotal
                        virustotal_search = virustotal.SearchVirustotal(word)
                        stor_lst.append(store(virustotal_search, engineitem, store_host=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)

                elif engineitem == 'yahoo':
                    from theHarvester.discovery import yahoosearch
                    try:
                        yahoo_search = yahoosearch.SearchYahoo(word, limit)
                        stor_lst.append(store(yahoo_search, engineitem, store_host=True, store_emails=True))
                    except Exception as e:
                        print(e)

                elif engineitem == 'zoomeye':
                    try:
                        from theHarvester.discovery import zoomeyesearch
                        zoomeye_search = zoomeyesearch.SearchZoomEye(word, limit)
                        stor_lst.append(store(zoomeye_search, engineitem, store_host=True, store_emails=True,
                                              store_ip=True, store_interestingurls=True, store_asns=True))
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
        else:
            try:
                # Check if dns_brute is defined
                rest_args.dns_brute
            except Exception:
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
                queue.task_done()

    async def handler(lst):
        queue = asyncio.Queue()

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
    return_ips: List = []
    if rest_args is not None and len(rest_filename) == 0 and rest_args.dns_brute is False:
        # Indicates user is using REST api but not wanting output to be saved to a file
        full = [host if ':' in host and word in host else word in host.split(':')[0] and host for host in full]
        full = list({host for host in full if host})
        full.sort()
        # cast to string so Rest API can understand type
        return_ips.extend([str(ip) for ip in sorted([netaddr.IPAddress(ip.strip()) for ip in set(all_ip)])])
        # return list(set(all_emails)), return_ips, full, '', ''
        return total_asns, interesting_urls, twitter_people_list_tracker, linkedin_people_list_tracker, \
            linkedin_links_tracker, all_urls, all_ip, all_emails, all_hosts
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
        print(f'\n[*] ASNS found: {len(total_asns)}')
        print('--------------------')
        total_asns = list(sorted(set(total_asns)))
        for asn in total_asns:
            print(asn)

    if len(interesting_urls) > 0:
        print(f'\n[*] Interesting Urls found: {len(interesting_urls)}')
        print('--------------------')
        interesting_urls = list(sorted(set(interesting_urls)))
        for iurl in interesting_urls:
            print(iurl)

    if len(twitter_people_list_tracker) == 0 and 'twitter' in engines:
        print('\n[*] No Twitter users found.\n\n')
    else:
        if len(twitter_people_list_tracker) >= 1:
            print('\n[*] Twitter Users found: ' + str(len(twitter_people_list_tracker)))
            print('---------------------')
            twitter_people_list_tracker = list(sorted(set(twitter_people_list_tracker)))
            for usr in twitter_people_list_tracker:
                print(usr)

    if len(linkedin_people_list_tracker) == 0 and 'linkedin' in engines:
        print('\n[*] No LinkedIn users found.\n\n')
    else:
        if len(linkedin_people_list_tracker) >= 1:
            print('\n[*] LinkedIn Users found: ' + str(len(linkedin_people_list_tracker)))
            print('---------------------')
            linkedin_people_list_tracker = list(sorted(set(linkedin_people_list_tracker)))
            for usr in linkedin_people_list_tracker:
                print(usr)

    if len(linkedin_links_tracker) == 0 and ('linkedin' in engines or 'rocketreach' in engines):
        print(f'\n[*] LinkedIn Links found: {len(linkedin_links_tracker)}')
        linkedin_links_tracker = list(sorted(set(linkedin_links_tracker)))
        print('---------------------')
        for link in linkedin_people_list_tracker:
            print(link)

    length_urls = len(all_urls)
    if length_urls == 0:
        if len(engines) >= 1 and 'trello' in engines:
            print('\n[*] No Trello URLs found.')
    else:
        total = length_urls
        print('\n[*] Trello URLs found: ' + str(total))
        print('--------------------')
        all_urls = list(sorted(set(all_urls)))
        for url in sorted(all_urls):
            print(url)

    if len(all_ip) == 0:
        print('\n[*] No IPs found.')
    else:
        print('\n[*] IPs found: ' + str(len(all_ip)))
        print('-------------------')
        # use netaddr as the list may contain ipv4 and ipv6 addresses
        ip_list = []
        for ip in set(all_ip):
            try:
                ip_list.append(netaddr.IPAddress(ip.strip()))
            except Exception:
                pass
        ip_list = sorted(ip_list)
        print('\n'.join(map(str, ip_list)))
        ip_list = list(ip_list)

    if len(all_emails) == 0:
        print('\n[*] No emails found.')
    else:
        print('\n[*] Emails found: ' + str(len(all_emails)))
        print('----------------------')
        all_emails = sorted(list(set(all_emails)))
        print(('\n'.join(all_emails)))

    if len(all_hosts) == 0:
        print('\n[*] No hosts found.\n\n')
    else:
        print('\n[*] Hosts found: ' + str(len(all_hosts)))
        print('---------------------')
        all_hosts = sorted(list(set(all_hosts)))
        db = stash.StashManager()
        full = [host if ':' in host and word in host else word in host.split(':')[0] and host for host in full]
        full = list({host for host in full if host})
        full.sort(key=lambda el: el.split(':')[0])
        for host in full:
            print(host)
        host_ip = [netaddr_ip.format() for netaddr_ip in sorted([netaddr.IPAddress(ip) for ip in ips])]
        await db.store_all(word, host_ip, 'ip', 'DNS-resolver')

    # DNS brute force
    if dnsbrute and dnsbrute[0] is True:
        print('\n[*] Starting DNS brute force.')
        dns_force = dnssearch.DnsForce(word, dnsserver, verbose=True)
        hosts, ips = await dns_force.run()
        hosts = list({host for host in hosts if ':' in host})
        hosts.sort(key=lambda el: el.split(':')[0])
        # Check if Rest API is being used if so return found hosts
        if dnsbrute[1]:
            return hosts
        print('\n[*] Hosts found after DNS brute force:')
        db = stash.StashManager()
        for host in hosts:
            print(host)
            full.append(host)
        await db.store_all(word, hosts, 'host', 'dns_bruteforce')

    # TakeOver Checking
    if takeover_status:
        print('\n[*] Performing subdomain takeover check')
        print('\n[*] Subdomain Takeover checking IS ACTIVE RECON')
        search_take = takeover.TakeOver(all_hosts)
        await search_take.process(proxy=use_proxy)

    # DNS reverse lookup
    dnsrev: List = []
    if dnslookup is True:
        print('\n[*] Starting active queries.')
        # load the reverse dns tools
        from theHarvester.discovery.dnssearch import (
            generate_postprocessing_callback,
            reverse_all_ips_in_range,
            serialize_ip_range)

        # reverse each iprange in a separate task
        __reverse_dns_tasks: Dict = {}
        for entry in host_ip:
            __ip_range = serialize_ip_range(ip=entry, netmask='24')
            if __ip_range and __ip_range not in set(__reverse_dns_tasks.keys()):
                print('\n[*] Performing reverse lookup on ' + __ip_range)
                __reverse_dns_tasks[__ip_range] = asyncio.create_task(reverse_all_ips_in_range(
                    iprange=__ip_range,
                    callback=generate_postprocessing_callback(
                        target=word,
                        local_results=dnsrev,
                        overall_results=full),
                    nameservers=list(map(str, dnsserver.split(','))) if dnsserver else None))

        # run all the reversing tasks concurrently
        await asyncio.gather(*__reverse_dns_tasks.values())

        # Display the newly found hosts
        print('\n[*] Hosts found after reverse lookup (in target domain):')
        print('--------------------------------------------------------')
        for xh in dnsrev:
            print(xh)

    # Virtual hosts search
    if virtual == 'basic':
        print('\n[*] Virtual hosts:')
        print('------------------')
        for data in host_ip:
            from theHarvester.discovery import bingsearch
            basic_search = bingsearch.SearchBing(data, limit, start)
            await basic_search.process_vhost()
            results = await basic_search.get_allhostnames()
            for result in results:
                result = re.sub(r'[[</?]*[\w]*>]*', '', result)
                result = re.sub('<', '', result)
                result = re.sub('>', '', result)
                print((data + '\t' + result))
                vhost.append(data + ':' + result)
                full.append(data + ':' + result)
        vhost = sorted(set(vhost))
    else:
        pass

    # Screenshots
    screenshot_tups = []
    if len(args.screenshot) > 0:
        import time
        from aiomultiprocess import Pool
        from theHarvester.screenshot.screenshot import ScreenShotter
        screen_shotter = ScreenShotter(args.screenshot)
        path_exists = screen_shotter.verify_path()
        # Verify path exists, if not create it or if user does not create it skips screenshot
        if path_exists:
            await screen_shotter.verify_installation()
            print(f'\nScreenshots can be found in: {screen_shotter.output}{screen_shotter.slash}')
            start_time = time.perf_counter()
            print('Filtering domains for ones we can reach')
            unique_resolved_domains = {url.split(':')[0]for url in full if ':' in url and 'www.' not in url}
            if len(unique_resolved_domains) > 0:
                # First filter out ones that didn't resolve
                print('Attempting to visit unique resolved domains, this is ACTIVE RECON')
                async with Pool(12) as pool:
                    results = await pool.map(screen_shotter.visit, list(unique_resolved_domains))
                    # Filter out domains that we couldn't connect to
                    unique_resolved_domains = list(sorted({tup[0] for tup in results if len(tup[1]) > 0}))
                async with Pool(3) as pool:
                    print(f'Length of unique resolved domains: {len(unique_resolved_domains)} chunking now!\n')
                    # If you have the resources you could make the function faster by increasing the chunk number
                    chunk_number = 14
                    for chunk in screen_shotter.chunk_list(unique_resolved_domains, chunk_number):
                        try:
                            screenshot_tups.extend(await pool.map(screen_shotter.take_screenshot, chunk))
                        except Exception as ee:
                            print(f'An exception has occurred while mapping: {ee}')
            end = time.perf_counter()
            # There is probably an easier way to do this
            total = end - start_time
            mon, sec = divmod(total, 60)
            hr, mon = divmod(mon, 60)
            total_time = "%02d:%02d" % (mon, sec)
            print(f'Finished taking screenshots in {total_time} seconds')
            print('[+] Note there may be leftover chrome processes you may have to kill manually\n')

    # Shodan
    shodanres = []
    if shodan is True:
        import json
        print('\033[94m[*] Searching Shodan. ')
        try:
            for ip in host_ip:
                print(('\tSearching for ' + ip))
                shodan = shodansearch.SearchShodan()
                shodandict = await shodan.search_ip(ip)
                await asyncio.sleep(2)
                rowdata = []
                for key, value in shodandict[ip].items():
                    if str(value) == 'Not in Shodan' or 'Error occurred in the Shodan IP search module' in str(value):
                        break
                    if isinstance(value, int):
                        value = str(value)

                    if isinstance(value, list):
                        value = ', '.join(map(str, value))
                    rowdata.append(value)
                shodanres.append(rowdata)
                print(json.dumps(shodandict[ip], indent=4, sort_keys=True))
                print('\n')
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
                for x in all_emails:
                    file.write('<email>' + x + '</email>')
                for x in full:
                    host, ip = x.split(':', 1) if ':' in x else (x, '')
                    if ip and len(ip) > 3:
                        file.write(f'<host><ip>{ip}</ip><hostname>{host}</hostname></host>')
                    else:
                        file.write(f'<host>{host}</host>')
                for x in vhost:
                    host, ip = x.split(':', 1) if ':' in x else (x, '')
                    if ip and len(ip) > 3:
                        file.write(f'<vhost><ip>{ip} </ip><hostname>{host}</hostname></vhost>')
                    else:
                        file.write(f'<vhost>{host}</vhost>')
                # TODO add Shodan output into XML report
                file.write('</theHarvester>')
                print('[*] XML File saved.')
        except Exception as error:
            print(f'[!] An error occurred while saving the XML file: {error}')

        try:
            # JSON REPORT SECTION
            filename = filename.rsplit('.', 1)[0] + '.json'
            # create dict with values for json output
            json_dict: Dict = dict()
            # determine if variable exists
            # it should but just a validation check
            if 'ip_list' in locals():
                if all_ip and len(all_ip) >= 1 and ip_list and len(ip_list) > 0:
                    json_dict["ips"] = [str(ip) for ip in ip_list]

            if len(all_emails) > 0:
                json_dict["emails"] = [email for email in all_emails]

            if len(full) > 0:
                json_dict["hosts"] = [host for host in full]

            if vhost and len(vhost) > 0:
                json_dict["vhosts"] = [host for host in vhost]

            if len(interesting_urls) > 0:
                json_dict["interesting_urls"] = interesting_urls

            if len(all_urls) > 0:
                json_dict["trello_urls"] = all_urls

            if len(total_asns) > 0:
                json_dict["asns"] = total_asns

            if len(twitter_people_list_tracker) > 0:
                json_dict["twitter_people"] = twitter_people_list_tracker

            if len(linkedin_people_list_tracker) > 0:
                json_dict["linkedin_people"] = linkedin_people_list_tracker

            if len(linkedin_links_tracker) > 0:
                json_dict["linkedin_links"] = linkedin_links_tracker

            json_dict["shodan"] = shodanres
            with open(filename, 'w+') as fp:
                # If you do not wish to install ujson you can do
                # fp.write(json.dumps(json_dict, sort_keys=True)
                fp.write(ujson.dumps(json_dict, sort_keys=True))
            print('[*] JSON File saved.')
        except Exception as er:
            print(f'[!] An error occurred while saving the JSON file: {er} ')
        print('\n\n')
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
