#!/usr/bin/env python3

from theHarvester.discovery import *
from theHarvester.discovery.constants import *
from theHarvester.lib import hostchecker
from theHarvester.lib import reportgraph
from theHarvester.lib import stash
from theHarvester.lib import statichtmlgenerator
from theHarvester.lib.core import *
import argparse
import asyncio
import datetime
import netaddr
import re
import sys
import time

Core.banner()


def start():
    parser = argparse.ArgumentParser(
        description='theHarvester is used to gather open source intelligence (OSINT) on a\n'
                    'company or domain.')
    parser.add_argument('-d', '--domain', help='company name or domain to search', required=True)
    parser.add_argument('-l', '--limit', help='limit the number of search results, default=500', default=500, type=int)
    parser.add_argument('-S', '--start', help='start with result number X, default=0', default=0, type=int)
    parser.add_argument('-g', '--google-dork', help='use Google Dorks for Google search', default=False, action='store_true')
    parser.add_argument('-p', '--port-scan', help='scan the detected hosts and check for Takeovers (21,22,80,443,8080)', default=False, action='store_true')
    parser.add_argument('-s', '--shodan', help='use Shodan to query discovered hosts', default=False, action='store_true')
    parser.add_argument('-v', '--virtual-host', help='verify host name via DNS resolution and search for virtual hosts', action='store_const', const='basic', default=False)
    parser.add_argument('-e', '--dns-server', help='DNS server to use for lookup')
    parser.add_argument('-t', '--dns-tld', help='perform a DNS TLD expansion discovery, default False', default=False)
    parser.add_argument('-n', '--dns-lookup', help='enable DNS server lookup, default False', default=False, action='store_true')
    parser.add_argument('-c', '--dns-brute', help='perform a DNS brute force on the domain', default=False, action='store_true')
    parser.add_argument('-f', '--filename', help='save the results to an HTML and/or XML file', default='', type=str)
    parser.add_argument('-b', '--source', help='''baidu, bing, bingapi, certspotter, crtsh, dnsdumpster,
                        dogpile, duckduckgo, github-code, google,
                        hunter, intelx,
                        linkedin, linkedin_links, netcraft, otx, securityTrails, spyse(disabled for now), threatcrowd,
                        trello, twitter, vhost, virustotal, yahoo, all''')

    args = parser.parse_args()
    try:
        db = stash.StashManager()
        db.do_init()
    except Exception:
        pass

    all_emails: list = []
    all_hosts: list = []
    all_ip: list = []
    dnsbrute = args.dns_brute
    dnslookup = args.dns_lookup
    dnsserver = args.dns_server
    dnstld = args.dns_tld
    engines = []
    filename: str = args.filename
    full: list = []
    google_dorking = args.google_dork
    host_ip: list = []
    limit: int = args.limit
    ports_scanning = args.port_scan
    shodan = args.shodan
    start: int = args.start
    takeover_check = False
    all_urls: list = []
    vhost: list = []
    virtual = args.virtual_host
    word: str = args.domain

    def store(search_engine: Any, source: str, process_param: Any = None, store_host: bool = False,
              store_emails: bool = False, store_ip: bool = False, store_people: bool = False,
              store_data: bool = False, store_links: bool = False, store_results: bool = False) -> None:
        """
        Persist details into the database.
        The details to be stored is controlled by the parameters passed to the method.

        :param search_engine: search engine to fetch details from
        :param source: source against which the details (corresponding to the search engine) need to be persisted
        :param process_param: any parameters to be passed to the search engine
                              eg: Google needs google_dorking
        :param store_host: whether to store hosts
        :param store_emails: whether to store emails
        :param store_ip: whether to store IP address
        :param store_people: whether to store user details
        :param store_data: whether to fetch host from method get_data() and persist
        :param store_links: whether to store links
        :param store_results: whether to fetch details from get_results() and persist
        """
        search_engine.process() if process_param is None else search_engine.process(process_param)
        db_stash = stash.StashManager()

        if store_host:
            host_names = filter(search_engine.get_hostnames())
            all_hosts.extend(host_names)
            db_stash.store_all(word, all_hosts, 'host', source)
        if store_emails:
            email_list = filter(search_engine.get_emails())
            all_emails.extend(email_list)
            db_stash.store_all(word, email_list, 'email', source)
        if store_ip:
            ips_list = search_engine.get_ips()
            all_ip.extend(ips_list)
            db_stash.store_all(word, all_ip, 'ip', source)
        if store_data:
            data = filter(search_engine.get_data())
            all_hosts.extend(data)
            db.store_all(word, all_hosts, 'host', source)
        if store_results:
            email_list, host_names, urls = search_engine.get_results()
            all_emails.extend(email_list)
            host_names = filter(host_names)
            all_urls.extend(filter(urls))
            all_hosts.extend(host_names)
            db.store_all(word, all_hosts, 'host', source)
            db.store_all(word, all_emails, 'email', source)
        if store_people:
            people_list = search_engine.get_people()
            db_stash.store_all(word, people_list, 'people', source)
            if len(people_list) == 0:
                print('\n[*] No users found.\n\n')
            else:
                print('\n[*] Users found: ' + str(len(people_list)))
                print('---------------------')
                for usr in sorted(list(set(people_list))):
                    print(usr)
        if store_links:
            links = search_engine.get_links()
            db.store_all(word, links, 'name', engineitem)
            if len(links) == 0:
                print('\n[*] No links found.\n\n')
            else:
                print(f'\n[*] Links found: {len(links)}')
                print('---------------------')
                for link in sorted(list(set(links))):
                    print(link)

    if args.source is not None:
        if args.source.lower() != 'all':
            engines = sorted(set(map(str.strip, args.source.split(','))))
        else:
            engines = Core.get_supportedengines()
        # Iterate through search engines in order
        if set(engines).issubset(Core.get_supportedengines()):
            print(f'\033[94m[*] Target: {word} \n \033[0m')

            for engineitem in engines:
                if engineitem == 'baidu':
                    print('\033[94m[*] Searching Baidu. \033[0m')
                    from theHarvester.discovery import baidusearch
                    try:
                        baidu_search = baidusearch.SearchBaidu(word, limit)
                        store(baidu_search, engineitem, store_host=True, store_emails=True)
                    except Exception:
                        pass

                elif engineitem == 'bing' or engineitem == 'bingapi':
                    print('\033[94m[*] Searching Bing. \033[0m')
                    from theHarvester.discovery import bingsearch
                    try:
                        bing_search = bingsearch.SearchBing(word, limit, start)
                        bingapi = ''
                        if engineitem == 'bingapi':
                            bingapi += 'yes'
                        else:
                            bingapi += 'no'
                        store(bing_search, 'bing', process_param=bingapi, store_host=True, store_emails=True)
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            pass

                elif engineitem == 'certspotter':
                    print('\033[94m[*] Searching CertSpotter. \033[0m')
                    from theHarvester.discovery import certspottersearch
                    try:
                        certspotter_search = certspottersearch.SearchCertspoter(word)
                        store(certspotter_search, engineitem, None, store_host=True)
                    except Exception as e:
                        print(e)

                elif engineitem == 'crtsh':
                    try:
                        print('\033[94m[*] Searching CRT.sh. \033[0m')
                        from theHarvester.discovery import crtsh
                        crtsh_search = crtsh.SearchCrtsh(word)
                        store(crtsh_search, 'CRTsh', store_data=True)

                    except Exception:
                        print(f'\033[93m[!] A timeout occurred with crtsh, cannot find {args.domain}\033[0m')

                elif engineitem == 'dnsdumpster':
                    try:
                        print('\033[94m[*] Searching DNSdumpster. \033[0m')
                        from theHarvester.discovery import dnsdumpster
                        dns_dumpster_search = dnsdumpster.SearchDnsDumpster(word)
                        store(dns_dumpster_search, engineitem, store_host=True)
                    except Exception as e:
                        print(f'\033[93m[!] An error occurred with dnsdumpster: {e} \033[0m')

                elif engineitem == 'dogpile':
                    try:
                        print('\033[94m[*] Searching Dogpile. \033[0m')
                        from theHarvester.discovery import dogpilesearch
                        dogpile_search = dogpilesearch.SearchDogpile(word, limit)
                        store(dogpile_search, engineitem, store_host=True, store_emails=True)
                    except Exception as e:
                        print(f'\033[93m[!] An error occurred with Dogpile: {e} \033[0m')

                elif engineitem == 'duckduckgo':
                    print('\033[94m[*] Searching DuckDuckGo. \033[0m')
                    from theHarvester.discovery import duckduckgosearch
                    duckduckgo_search = duckduckgosearch.SearchDuckDuckGo(word, limit)
                    store(duckduckgo_search, engineitem, store_host=True, store_emails=True)

                elif engineitem == 'github-code':
                    print('\033[94m[*] Searching Github (code). \033[0m')
                    try:
                        from theHarvester.discovery import githubcode
                        github_search = githubcode.SearchGithubCode(word, limit)
                        store(github_search, engineitem, store_host=True, store_emails=True)
                    except MissingKey as ex:
                        print(ex)
                    else:
                        pass

                elif engineitem == 'exalead':
                    print('\033[94m[*] Searching Exalead \033[0m')
                    from theHarvester.discovery import exaleadsearch
                    exalead_search = exaleadsearch.SearchExalead(word, limit, start)
                    store(exalead_search, engineitem, store_host=True, store_emails=True)

                elif engineitem == 'google':
                    print('\033[94m[*] Searching Google. \033[0m')
                    from theHarvester.discovery import googlesearch
                    google_search = googlesearch.SearchGoogle(word, limit, start)
                    store(google_search, engineitem, process_param=google_dorking, store_host=True, store_emails=True)

                elif engineitem == 'hunter':
                    print('\033[94m[*] Searching Hunter. \033[0m')
                    from theHarvester.discovery import huntersearch
                    # Import locally or won't work.
                    try:
                        hunter_search = huntersearch.SearchHunter(word, limit, start)
                        store(hunter_search, engineitem, store_host=True, store_emails=True)
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            pass

                elif engineitem == 'intelx':
                    print('\033[94m[*] Searching Intelx. \033[0m')
                    from theHarvester.discovery import intelxsearch
                    # Import locally or won't work.
                    try:
                        intelx_search = intelxsearch.SearchIntelx(word, limit)
                        store(intelx_search, engineitem, store_host=True, store_emails=True)
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            print(f'An exception has occurred in Intelx search: {e}')

                elif engineitem == 'linkedin':
                    print('\033[94m[*] Searching Linkedin. \033[0m')
                    from theHarvester.discovery import linkedinsearch
                    linkedin_search = linkedinsearch.SearchLinkedin(word, limit)
                    store(linkedin_search, engineitem, store_people=True)

                elif engineitem == 'linkedin_links':
                    print('\033[94m[*] Searching Linkedin. \033[0m')
                    from theHarvester.discovery import linkedinsearch
                    linkedin_links_search = linkedinsearch.SearchLinkedin(word, limit)
                    store(linkedin_links_search, 'linkedin', store_links=True)

                elif engineitem == 'netcraft':
                    print('\033[94m[*] Searching Netcraft. \033[0m')
                    from theHarvester.discovery import netcraft
                    netcraft_search = netcraft.SearchNetcraft(word)
                    store(netcraft_search, engineitem, store_host=True)

                elif engineitem == 'otx':
                    print('\033[94m[*] Searching AlienVault OTX. \033[0m')
                    from theHarvester.discovery import otxsearch
                    try:
                        otxsearch_search = otxsearch.SearchOtx(word)
                        store(otxsearch_search, engineitem, store_host=True, store_ip=True)
                    except Exception as e:
                        print(e)

                elif engineitem == 'securityTrails':
                    print('\033[94m[*] Searching SecurityTrails. \033[0m')
                    from theHarvester.discovery import securitytrailssearch
                    try:
                        securitytrails_search = securitytrailssearch.SearchSecuritytrail(word)
                        store(securitytrails_search, engineitem, store_host=True, store_ip=True)
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            pass

                elif engineitem == 'suip':
                    print('\033[94m[*] Searching Suip. This module can take 10+ mins to run but it is worth it.\033[0m')
                    from theHarvester.discovery import suip
                    try:
                        suip_search = suip.SearchSuip(word)
                        store(suip_search, engineitem, store_host=True)
                    except Exception as e:
                        print(e)

                # elif engineitem == 'spyse':
                #     print('\033[94m[*] Searching Spyse. \033[0m')
                #     from theHarvester.discovery import spyse
                #     try:
                #         spysesearch_search = spyse.SearchSpyse(word)
                #         spysesearch_search.process()
                #         hosts = filter(spysesearch_search.get_hostnames())
                #         all_hosts.extend(list(hosts))
                #         # ips = filter(spysesearch_search.get_ips())
                #         # all_ip.extend(list(ips))
                #         all_hosts.extend(hosts)
                #         db = stash.stash_manager()
                #         db.store_all(word, all_hosts, 'host', 'spyse')
                #         # db.store_all(word, all_ip, 'ip', 'spyse')
                #     except Exception as e:
                #         print(e)

                elif engineitem == 'threatcrowd':
                    print('\033[94m[*] Searching Threatcrowd. \033[0m')
                    from theHarvester.discovery import threatcrowd
                    try:
                        threatcrowd_search = threatcrowd.SearchThreatcrowd(word)
                        store(threatcrowd_search, engineitem, store_host=True)
                    except Exception as e:
                        print(e)

                elif engineitem == 'trello':
                    print('\033[94m[*] Searching Trello. \033[0m')
                    from theHarvester.discovery import trello
                    # Import locally or won't work.
                    trello_search = trello.SearchTrello(word)
                    store(trello_search, engineitem, store_results=True)

                elif engineitem == 'twitter':
                    print('\033[94m[*] Searching Twitter usernames using Google. \033[0m')
                    from theHarvester.discovery import twittersearch
                    twitter_search = twittersearch.SearchTwitter(word, limit)
                    store(twitter_search, engineitem, store_people=True)

                elif engineitem == 'virustotal':
                    print('\033[94m[*] Searching VirusTotal. \033[0m')
                    from theHarvester.discovery import virustotal
                    virustotal_search = virustotal.SearchVirustotal(word)
                    store(virustotal_search, engineitem, store_host=True)

                elif engineitem == 'yahoo':
                    print('\033[94m[*] Searching Yahoo. \033[0m')
                    from theHarvester.discovery import yahoosearch
                    yahoo_search = yahoosearch.SearchYahoo(word, limit)
                    store(yahoo_search, engineitem, store_host=True, store_emails=True)
        else:
            print('\033[93m[!] Invalid source.\n\n \033[0m')
            sys.exit(1)

    # Sanity check to see if all_emails and all_hosts are defined.
    try:
        all_emails
    except NameError:
        print('\n\n\033[93m[!] No emails found because all_emails is not defined.\n\n \033[0m')
        sys.exit(1)
    try:
        all_hosts
    except NameError:
        print('\n\n\033[93m[!] No hosts found because all_hosts is not defined.\n\n \033[0m')
        sys.exit(1)

    # Results
    if len(all_ip) == 0:
        print('\n[*] No IPs found.')
    else:
        print('\n[*] IPs found: ' + str(len(all_ip)))
        print('-------------------')
        # use netaddr as the list may contain ipv4 and ipv6 addresses
        ip_list = sorted([netaddr.IPAddress(ip.strip()) for ip in set(all_ip)])
        print('\n'.join(map(str, ip_list)))

    if len(all_emails) == 0:
        print('\n[*] No emails found.')
    else:
        print('\n[*] Emails found: ' + str(len(all_emails)))
        print('----------------------')
        print(('\n'.join(sorted(list(set(all_emails))))))

    if len(all_hosts) == 0:
        print('\n[*] No hosts found.\n\n')
    else:
        print('\n[*] Hosts found: ' + str(len(all_hosts)))
        print('---------------------')
        all_hosts = sorted(list(set(all_hosts)))
        full_host = hostchecker.Checker(all_hosts)
        full, ips = asyncio.run(full_host.check())
        db = stash.StashManager()
        for host in full:
            host = str(host)
            print(host)
        host_ip = [netaddr_ip.format() for netaddr_ip in sorted([netaddr.IPAddress(ip) for ip in ips])]
        db.store_all(word, host_ip, 'ip', 'DNS-resolver')
    length_urls = len(all_urls)
    if length_urls == 0:
        if len(engines) >= 1 and 'trello' in engines:
            print('\n[*] No Trello URLs found.')
    else:
        total = length_urls
        print('\n[*] Trello URLs found: ' + str(total))
        print('--------------------')
        for url in sorted(all_urls):
            print(url)

    # DNS brute force
    # dnsres = []
    if dnsbrute is True:
        print('\n[*] Starting DNS brute force.')
        a = dnssearch.DnsForce(word, dnsserver, verbose=True)
        a.process()
        # print('\n[*] Hosts found after DNS brute force:')
        # for y in res:
        # print('-------------------------------------')
        #    print(y)
        #   dnsres.append(y.split(':')[0])
        #    if y not in full:
        #        full.append(y)
        # db = stash.stash_manager()
        # db.store_all(word, dnsres, 'host', 'dns_bruteforce')

    # Port scanning
    if ports_scanning is True:
        print('\n\n[*] Scanning ports (active).\n')
        for x in full:
            host = x.split(':')[1]
            domain = x.split(':')[0]
            if host != 'empty':
                print(('[*] Scanning ' + host))
                ports = [21, 22, 80, 443, 8080]
                try:
                    scan = port_scanner.PortScan(host, ports)
                    openports = scan.process()
                    if len(openports) > 1:
                        print(('\t[*] Detected open ports: ' + ','.join(str(e) for e in openports)))
                    takeover_check = 'True'
                    if takeover_check == 'True' and len(openports) > 0:
                        search_take = takeover.TakeOver(domain)
                        search_take.process()
                except Exception as e:
                    print(e)

    # DNS reverse lookup
    dnsrev = []
    if dnslookup is True:
        print('\n[*] Starting active queries.')
        analyzed_ranges = []
        for entry in host_ip:
            print(entry)
            ip = entry.split(':')[0]
            ip_range = ip.split('.')
            ip_range[3] = '0/24'
            s = '.'
            ip_range = s.join(ip_range)
            if not analyzed_ranges.count(ip_range):
                print('[*] Performing reverse lookup in ' + ip_range)
                a = dnssearch.DnsReverse(ip_range, True)
                a.list()
                res = a.process()
                analyzed_ranges.append(ip_range)
            else:
                continue
            for entries in res:
                if entries.count(word):
                    dnsrev.append(entries)
                    if entries not in full:
                        full.append(entries)
        print('[*] Hosts found after reverse lookup (in target domain):')
        print('--------------------------------------------------------')
        for xh in dnsrev:
            print(xh)

    # DNS TLD expansion
    dnstldres = []
    if dnstld is True:
        print('[*] Starting DNS TLD expansion.')
        a = dnssearch.DnsTld(word, dnsserver, verbose=True)
        res = a.process()
        print('\n[*] Hosts found after DNS TLD expansion:')
        print('----------------------------------------')
        for y in res:
            print(y)
            dnstldres.append(y)
            if y not in full:
                full.append(y)

    # Virtual hosts search
    if virtual == 'basic':
        print('\n[*] Virtual hosts:')
        print('------------------')
        for l in host_ip:
            basic_search = bingsearch.SearchBing(l, limit, start)
            basic_search.process_vhost()
            results = basic_search.get_allhostnames()
            for result in results:
                result = re.sub(r'[[\<\/?]*[\w]*>]*', '', result)
                result = re.sub('<', '', result)
                result = re.sub('>', '', result)
                print((l + '\t' + result))
                vhost.append(l + ':' + result)
                full.append(l + ':' + result)
        vhost = sorted(set(vhost))
    else:
        pass

    # Shodan
    shodanres = []
    if shodan is True:
        import texttable
        tab = texttable.Texttable()
        header = ['IP address', 'Hostname', 'Org', 'Services:Ports', 'Technologies']
        tab.header(header)
        tab.set_cols_align(['c', 'c', 'c', 'c', 'c'])
        tab.set_cols_valign(['m', 'm', 'm', 'm', 'm'])
        tab.set_chars(['-', '|', '+', '#'])
        tab.set_cols_width([15, 20, 15, 15, 18])
        print('\033[94m[*] Searching Shodan. \033[0m')
        try:
            for ip in host_ip:
                print(('\tSearching for ' + ip))
                shodan = shodansearch.SearchShodan()
                rowdata = shodan.search_ip(ip)
                time.sleep(2)
                tab.add_row(rowdata)
            printedtable = tab.draw()
            print(printedtable)
        except Exception as e:
            print(f'\033[93m[!] An error occurred with Shodan: {e} \033[0m')
    else:
        pass

    # Here we need to add explosion mode.
    # We have to take out the TLDs to do this.
    if args.dns_tld is not False:
        counter = 0
        for word in vhost:
            search = googlesearch.SearchGoogle(word, limit, counter)
            search.process(google_dorking)
            emails = search.get_emails()
            hosts = search.get_hostnames()
            print(emails)
            print(hosts)
    else:
        pass

    # Reporting
    if filename != "":
        try:
            print('\n[*] Reporting started.')
            db = stash.StashManager()
            scanboarddata = db.getscanboarddata()
            latestscanresults = db.getlatestscanresults(word)
            previousscanresults = db.getlatestscanresults(word, previousday=True)
            latestscanchartdata = db.latestscanchartdata(word)
            scanhistorydomain = db.getscanhistorydomain(word)
            pluginscanstatistics = db.getpluginscanstatistics()
            generator = statichtmlgenerator.HtmlGenerator(word)
            HTMLcode = generator.beginhtml()
            HTMLcode += generator.generatelatestscanresults(latestscanresults)
            HTMLcode += generator.generatepreviousscanresults(previousscanresults)
            graph = reportgraph.GraphGenerator(word)
            HTMLcode += graph.drawlatestscangraph(word, latestscanchartdata)
            HTMLcode += graph.drawscattergraphscanhistory(word, scanhistorydomain)
            HTMLcode += generator.generatepluginscanstatistics(pluginscanstatistics)
            HTMLcode += generator.generatedashboardcode(scanboarddata)
            HTMLcode += '<p><span style="color: #000000;">Report generated on ' + str(
                datetime.datetime.now()) + '</span></p>'
            HTMLcode += '''
            </body>
            </html>
            '''
            Html_file = open(filename, 'w')
            Html_file.write(HTMLcode)
            Html_file.close()
            print('[*] Reporting finished.')
            print('[*] Saving files.')
        except Exception as e:
            print(e)
            print('\n\033[93m[!] An error occurred while creating the output file.\n\n \033[0m')
            sys.exit(1)

        try:
            filename = filename.split('.')[0] + '.xml'
            file = open(filename, 'w')
            file.write('<?xml version="1.0" encoding="UTF-8"?><theHarvester>')
            for x in all_emails:
                file.write('<email>' + x + '</email>')
            for x in full:
                x = x.split(':')
                if len(x) == 2:
                    file.write(
                        '<host>' + '<ip>' + x[1] + '</ip><hostname>' + x[0] + '</hostname>' + '</host>')
                else:
                    file.write('<host>' + x + '</host>')
            for x in vhost:
                x = x.split(':')
                if len(x) == 2:
                    file.write(
                        '<vhost>' + '<ip>' + x[1] + '</ip><hostname>' + x[0] + '</hostname>' + '</vhost>')
                else:
                    file.write('<vhost>' + x + '</vhost>')
            if shodanres != []:
                shodanalysis = []
                for x in shodanres:
                    res = x.split('SAPO')
                    file.write('<shodan>')
                    file.write('<host>' + res[0] + '</host>')
                    file.write('<port>' + res[2] + '</port>')
                    file.write('<banner><!--' + res[1] + '--></banner>')
                    reg_server = re.compile('Server:.*')
                    temp = reg_server.findall(res[1])
                    if temp:
                        shodanalysis.append(res[0] + ':' + temp[0])
                    file.write('</shodan>')
                if shodanalysis:
                    shodanalysis = sorted(set(shodanalysis))
                    file.write('<servers>')
                    for x in shodanalysis:
                        file.write('<server>' + x + '</server>')
                    file.write('</servers>')

            file.write('</theHarvester>')
            file.flush()
            file.close()
            print('[*] Files saved.')
        except Exception as er:
            print(f'\033[93m[!] An error occurred while saving the XML file: {er} \033[0m')
        print('\n\n')
        sys.exit(0)


def entry_point():
    try:
        start()
    except KeyboardInterrupt:
        print('\n\n\033[93m[!] ctrl+c detected from user, quitting.\n\n \033[0m')
    except Exception as error_entry_point:
        print(error_entry_point)
        sys.exit(1)


if __name__ == '__main__':
    entry_point()
