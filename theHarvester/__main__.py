#!/usr/bin/env python3

from theHarvester.discovery import *
from theHarvester.discovery.constants import *
from theHarvester.lib import hostchecker
from theHarvester.lib import htmlExport
from theHarvester.lib import reportgraph
from theHarvester.lib import stash
from theHarvester.lib import statichtmlgenerator
from theHarvester.lib.core import *
from platform import python_version
import argparse
import datetime
import ipaddress
import re
import sys
import time

try:
    import bs4
except ImportError:
    print('\n\033[93m[!] BeautifulSoup library not found, please install before proceeding.\n\n \033[0m')
    sys.exit(1)

try:
    import requests
except ImportError:
    print('\n\033[93m[!] Requests library not found, please install before proceeding.\n\n \033[0m')
    sys.exit(1)

Core.banner()


def modified_source(excluded_engines):
    engines = Core.get_supportedengines()
    engines.remove('all')
    excluded_engines = set(map(str.strip, excluded_engines.split(',')))
    return engines.difference(excluded_engines)


def start():
    parser = argparse.ArgumentParser(description='theHarvester is used to gather open source intelligence (OSINT) on a\n'
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
    parser.add_argument('-b', '--source', help='''baidu, bing, bingapi, censys, crtsh, dnsdumpster,
                        dogpile, duckduckgo, google, 
                        google-certificates, hunter, intelx,
                        linkedin, netcraft, securityTrails, threatcrowd,
                        trello, twitter, vhost, virustotal, yahoo, all''')
    parser.add_argument('-x', '--exclude', help='exclude options when using all sources', type=str)
    args = parser.parse_args()

    try:
        db = stash.stash_manager()
        db.do_init()
    except Exception:
        pass

    all_emails = []
    all_hosts = []
    all_ip = []
    dnsbrute = args.dns_brute
    dnslookup = args.dns_lookup
    dnsserver = args.dns_server
    dnstld = args.dns_tld
    filename = args.filename
    full = []
    google_dorking = args.google_dork
    host_ip = []
    limit = args.limit
    ports_scanning = args.port_scan
    shodan = args.shodan
    start = args.start
    takeover_check = False
    trello_info = ([], False)
    vhost = []
    virtual = args.virtual_host
    word = args.domain

    if args.source is not None:
        engines = set(map(str.strip, args.source.split(',')))
        if args.source == 'all' and args.exclude is not None:
            engines = modified_source(args.exclude)
        if set(engines).issubset(Core.get_supportedengines()):
            print(f'\033[94m[*] Target: {word} \n \033[0m')
            for engineitem in engines:
                if engineitem == 'baidu':
                    print('\033[94m[*] Searching Baidu. \033[0m')
                    try:
                        search = baidusearch.SearchBaidu(word, limit)
                        search.process()
                        all_emails = filter(search.get_emails())
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'baidu')
                        db.store_all(word, all_emails, 'email', 'baidu')
                    except Exception:
                        pass

                elif engineitem == 'bing' or engineitem == 'bingapi':
                    print('\033[94m[*] Searching Bing. \033[0m')
                    try:
                        search = bingsearch.SearchBing(word, limit, start)
                        bingapi = ''
                        if engineitem == 'bingapi':
                            bingapi += 'yes'
                        else:
                            bingapi += 'no'
                        search.process(bingapi)
                        all_emails = filter(search.get_emails())
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'email', 'bing')
                        db.store_all(word, all_hosts, 'host', 'bing')
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            pass

                elif engineitem == 'censys':
                    print('\033[94m[*] Searching Censys. \033[0m')
                    from theHarvester.discovery import censys
                    # Import locally or won't work
                    search = censys.SearchCensys(word, limit)
                    search.process()
                    all_ip = search.get_ipaddresses()
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'censys')
                    db.store_all(word, all_ip, 'ip', 'censys')

                elif engineitem == 'crtsh':
                    print('\033[94m[*] Searching CRT.sh. \033[0m')
                    search = crtsh.SearchCrtsh(word)
                    search.process()
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'CRTsh')

                elif engineitem == 'dnsdumpster':
                    try:
                        print('\033[94m[*] Searching DNSdumpster. \033[0m')
                        from theHarvester.discovery import dnsdumpster
                        search = dnsdumpster.search_dnsdumpster(word)
                        search.process()
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'dnsdumpster')
                    except Exception as e:
                        print(f'\033[93m[!] An error occurred with dnsdumpster: {e} \033[0m')

                elif engineitem == 'dogpile':
                    try:
                        print('\033[94m[*] Searching Dogpile. \033[0m')
                        search = dogpilesearch.SearchDogpile(word, limit)
                        search.process()
                        emails = filter(search.get_emails())
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        all_emails.extend(emails)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'email', 'dogpile')
                        db.store_all(word, all_hosts, 'host', 'dogpile')
                    except Exception as e:
                        print(f'\033[93m[!] An error occurred with Dogpile: {e} \033[0m')

                elif engineitem == 'duckduckgo':
                    print('\033[94m[*] Searching DuckDuckGo. \033[0m')
                    from theHarvester.discovery import duckduckgosearch
                    search = duckduckgosearch.SearchDuckDuckGo(word, limit)
                    search.process()
                    emails = filter(search.get_emails())
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    all_emails.extend(emails)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'email', 'duckduckgo')
                    db.store_all(word, all_hosts, 'host', 'duckduckgo')

                elif engineitem == 'google':
                    print('\033[94m[*] Searching Google. \033[0m')
                    search = googlesearch.search_google(word, limit, start)
                    search.process(google_dorking)
                    emails = filter(search.get_emails())
                    all_emails.extend(emails)
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'google')
                    db.store_all(word, all_emails, 'email', 'google')

                elif engineitem == 'google-certificates':
                    print('\033[94m[*] Searching Google Certificate transparency report. \033[0m')
                    search = googlecertificates.SearchGoogleCertificates(word, limit, start)
                    search.process()
                    hosts = filter(search.get_domains())
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'google-certificates')

                elif engineitem == 'hunter':
                    print('\033[94m[*] Searching Hunter. \033[0m')
                    from theHarvester.discovery import huntersearch
                    # Import locally or won't work.
                    try:
                        search = huntersearch.SearchHunter(word, limit, start)
                        search.process()
                        emails = filter(search.get_emails())
                        all_emails.extend(emails)
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'hunter')
                        db.store_all(word, all_emails, 'email', 'hunter')
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
                        search = intelxsearch.SearchIntelx(word, limit)
                        search.process()
                        emails = filter(search.get_emails())
                        all_emails.extend(emails)
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'intelx')
                        db.store_all(word, all_emails, 'email', 'intelx')
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            print(e)

                elif engineitem == 'linkedin':
                    print('\033[94m[*] Searching Linkedin. \033[0m')
                    search = linkedinsearch.SearchLinkedin(word, limit)
                    search.process()
                    people = search.get_people()
                    db = stash.stash_manager()
                    db.store_all(word, people, 'name', 'linkedin')

                    if len(people) == 0:
                        print('\n[*] No users found Linkedin.\n\n')
                    else:
                        print(f'\n[*] Users found: {len(people)}')
                        print('---------------------')
                        for user in sorted(list(set(people))):
                            print(user)
                    sys.exit(0)

                elif engineitem == 'netcraft':
                    print('\033[94m[*] Searching Netcraft. \033[0m')
                    search = netcraft.SearchNetcraft(word)
                    search.process()
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'netcraft')

                elif engineitem == 'securityTrails':
                    print('\033[94m[*] Searching SecurityTrails. \033[0m')
                    from theHarvester.discovery import securitytrailssearch
                    try:
                        search = securitytrailssearch.search_securitytrail(word)
                        search.process()
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, hosts, 'host', 'securityTrails')
                        ips = search.get_ips()
                        all_ip.extend(ips)
                        db = stash.stash_manager()
                        db.store_all(word, ips, 'ip', 'securityTrails')
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            pass

                elif engineitem == 'threatcrowd':
                    print('\033[94m[*] Searching Threatcrowd. \033[0m')
                    try:
                        search = threatcrowd.SearchThreatcrowd(word)
                        search.process()
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'threatcrowd')
                    except Exception:
                        pass

                elif engineitem == 'trello':
                    print('\033[94m[*] Searching Trello. \033[0m')
                    from theHarvester.discovery import trello
                    # Import locally or won't work.
                    search = trello.search_trello(word, limit)
                    search.process()
                    emails = filter(search.get_emails())
                    all_emails.extend(emails)
                    info = search.get_urls()
                    hosts = filter(info[0])
                    trello_info = (info[1], True)
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, hosts, 'host', 'trello')
                    db.store_all(word, emails, 'email', 'trello')

                elif engineitem == 'twitter':
                    print('\033[94m[*] Searching Twitter usernames using Google. \033[0m')
                    search = twittersearch.search_twitter(word, limit)
                    search.process()
                    people = search.get_people()
                    db = stash.stash_manager()
                    db.store_all(word, people, 'name', 'twitter')

                    if len(people) == 0:
                        print('\n[*] No users found.\n\n')
                    else:
                        print('\n[*] Users found: ' + str(len(people)))
                        print('---------------------')
                        for user in sorted(list(set(people))):
                            print(user)

                elif engineitem == 'virustotal':
                    print('\033[94m[*] Searching VirusTotal. \033[0m')
                    search = virustotal.SearchVirustotal(word)
                    search.process()
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'virustotal')

                elif engineitem == 'yahoo':
                    print('\033[94m[*] Searching Yahoo. \033[0m')
                    search = yahoosearch.search_yahoo(word, limit)
                    search.process()
                    hosts = search.get_hostnames()
                    emails = search.get_emails()
                    all_hosts.extend(filter(hosts))
                    all_emails.extend(filter(emails))
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'yahoo')
                    db.store_all(word, all_emails, 'email', 'yahoo')

                elif engineitem == 'all':
                    print(('[*] Full harvest on ' + word))
                    all_emails = []
                    all_hosts = []
                    try:
                        print('\033[94m[*] Searching Baidu. \033[0m')
                        search = baidusearch.SearchBaidu(word, limit)
                        search.process()
                        all_emails = filter(search.get_emails())
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'baidu')
                        db.store_all(word, all_emails, 'email', 'baidu')
                    except Exception:
                        pass
                    try:
                        print('\033[94m[*] Searching Bing. \033[0m')
                        bingapi = 'no'
                        search = bingsearch.SearchBing(word, limit, start)
                        search.process(bingapi)
                        emails = filter(search.get_emails())
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'bing')
                        all_emails.extend(emails)
                        all_emails = sorted(set(all_emails))
                        db.store_all(word, all_emails, 'email', 'bing')
                    except Exception:
                        pass

                    print('\033[94m[*] Searching Censys. \033[0m')
                    from theHarvester.discovery import censys
                    search = censys.SearchCensys(word, limit)
                    search.process()
                    ips = search.get_ipaddresses()
                    setips = set(ips)
                    uniqueips = list(setips)  # Remove duplicates.
                    all_ip.extend(uniqueips)
                    hosts = filter(search.get_hostnames())
                    sethosts = set(hosts)
                    uniquehosts = list(sethosts)  # Remove duplicates.
                    all_hosts.extend(uniquehosts)
                    db = stash.stash_manager()
                    db.store_all(word, uniquehosts, 'host', 'censys')
                    db.store_all(word, uniqueips, 'ip', 'censys')

                    print('\033[94m[*] Searching CRT.sh. \033[0m')
                    search = crtsh.SearchCrtsh(word)
                    search.process()
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'CRTsh')

                    try:
                        print('\033[94m[*] Searching DNSdumpster. \033[0m')
                        from theHarvester.discovery import dnsdumpster
                        search = dnsdumpster.search_dnsdumpster(word)
                        search.process()
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'dnsdumpster')
                    except Exception as e:
                        print(f'\033[93m[!] An error occurred with dnsdumpster: {e} \033[0m')

                    print('\033[94m[*] Searching Dogpile. \033[0m')
                    try:
                        search = dogpilesearch.SearchDogpile(word, limit)
                        search.process()
                        emails = filter(search.get_emails())
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        all_emails.extend(emails)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'email', 'dogpile')
                        db.store_all(word, all_hosts, 'host', 'dogpile')
                    except Exception as e:
                        print(f'An exception has occurred in Dogpile: {e}')

                    print('\033[94m[*] Searching DuckDuckGo. \033[0m')
                    from theHarvester.discovery import duckduckgosearch
                    search = duckduckgosearch.SearchDuckDuckGo(word, limit)
                    search.process()
                    emails = filter(search.get_emails())
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    all_emails.extend(emails)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'email', 'duckduckgo')
                    db.store_all(word, all_hosts, 'host', 'duckduckgo')

                    print('\033[94m[*] Searching Google. \033[0m')
                    search = googlesearch.search_google(word, limit, start)
                    search.process(google_dorking)
                    emails = filter(search.get_emails())
                    hosts = filter(search.get_hostnames())
                    all_emails.extend(emails)
                    db = stash.stash_manager()
                    db.store_all(word, all_emails, 'email', 'google')
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'google')

                    print('\033[94m[*] Searching Google Certificate transparency report. \033[0m')
                    search = googlecertificates.SearchGoogleCertificates(word, limit, start)
                    search.process()
                    domains = filter(search.get_domains())
                    all_hosts.extend(domains)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'google-certificates')

                    print('\033[94m[*] Searching Hunter. \033[0m')
                    from theHarvester.discovery import huntersearch
                    # Import locally.
                    try:
                        search = huntersearch.SearchHunter(word, limit, start)
                        search.process()
                        emails = filter(search.get_emails())
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, hosts, 'host', 'hunter')
                        all_emails.extend(emails)
                        all_emails = sorted(set(all_emails))
                        db.store_all(word, all_emails, 'email', 'hunter')
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            print(f'Error occured in hunter: {e}')

                    print('\033[94m[*] Searching Intelx. \033[0m')
                    from theHarvester.discovery import intelxsearch
                    # Import locally or won't work.
                    try:
                        search = intelxsearch.SearchIntelx(word, limit)
                        search.process()
                        emails = filter(search.get_emails())
                        all_emails.extend(emails)
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'intelx')
                        db.store_all(word, all_emails, 'email', 'intelx')
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            print(e)

                    print('\033[94m[*] Searching Linkedin. \033[0m')
                    search = linkedinsearch.SearchLinkedin(word, limit)
                    search.process()
                    people = search.get_people()
                    db = stash.stash_manager()
                    db.store_all(word, people, 'name', 'linkedin')

                    if len(people) == 0:
                        print('\n[*] No users found.\n\n')
                    else:
                        print('\n[*] Users found: ' + str(len(people)))
                        print('---------------------')
                        for user in sorted(list(set(people))):
                            print(user)

                    print('\033[94m[*] Searching Netcraft. \033[0m')
                    search = netcraft.SearchNetcraft(word)
                    search.process()
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'netcraft')

                    print('\033[94m[*] Searching SecurityTrails. \033[0m')
                    from theHarvester.discovery import securitytrailssearch
                    try:
                        search = securitytrailssearch.search_securitytrail(word)
                        search.process()
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, hosts, 'host', 'securityTrails')
                        ips = search.get_ips()
                        all_ip.extend(ips)
                        db = stash.stash_manager()
                        db.store_all(word, ips, 'ip', 'securityTrails')
                    except Exception as e:
                        if isinstance(e, MissingKey):
                            print(e)
                        else:
                            pass

                    print('\033[94m[*] Searching Threatcrowd. \033[0m')
                    try:
                        search = threatcrowd.SearchThreatcrowd(word)
                        search.process()
                        hosts = filter(search.get_hostnames())
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'threatcrowd')
                    except Exception as error:
                        print(error)

                    print('\033[94m[*] Searching Trello. \033[0m')
                    from theHarvester.discovery import trello
                    # Import locally or won't work.
                    search = trello.search_trello(word, limit)
                    search.process()
                    emails = filter(search.get_emails())
                    all_emails.extend(emails)
                    info = search.get_urls()
                    hosts = filter(info[0])
                    trello_info = (info[1], True)
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, hosts, 'host', 'trello')
                    db.store_all(word, emails, 'email', 'trello')

                    try:
                        print('\033[94m[*] Searching Twitter. \033[0m')
                        search = twittersearch.search_twitter(word, limit)
                        search.process()
                        people = search.get_people()
                        db = stash.stash_manager()
                        db.store_all(word, people, 'name', 'twitter')
                        print('\nUsers from Twitter:')
                        print('-------------------')
                        for user in people:
                            print(user)
                    except Exception as error:
                        print(error)

                    print('\n[*] Virtual hosts:')
                    print('------------------')
                    for l in host_ip:
                        search = bingsearch.SearchBing(l, limit, start)
                        search.process_vhost()
                        res = search.get_allhostnames()
                        for x in res:
                            x = re.sub(r'[[\<\/?]*[\w]*>]*', '', x)
                            x = re.sub('<', '', x)
                            x = re.sub('>', '', x)
                            print((l + '\t' + x))
                            vhost.append(l + ':' + x)
                            full.append(l + ':' + x)
                    vhost = sorted(set(vhost))

                    print('\033[94m[*] Searching VirusTotal. \033[0m')
                    search = virustotal.SearchVirustotal(word)
                    search.process()
                    hosts = filter(search.get_hostnames())
                    all_hosts.extend(hosts)
                    db = stash.stash_manager()
                    db.store_all(word, all_hosts, 'host', 'virustotal')

                    try:
                        print('\033[94m[*] Searching Yahoo. \033[0m')
                        search = yahoosearch.search_yahoo(word, limit)
                        search.process()
                        hosts = search.get_hostnames()
                        emails = search.get_emails()
                        all_hosts.extend(filter(hosts))
                        all_emails.extend(filter(emails))
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'yahoo')
                        db.store_all(word, all_emails, 'email', 'yahoo')
                    except Exception as e:
                        print(f'An exception occurred in yahoo: {e}')
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
        ips = sorted(ipaddress.ip_address(line.strip()) for line in set(all_ip))
        print('\n'.join(map(str, ips)))

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
        full = full_host.check()
        for host in full:
            ip = host.split(':')[1]
            print(host)
            if ip != 'empty':
                if host_ip.count(ip.lower()):
                    pass
                else:
                    host_ip.append(ip.lower())

        db = stash.stash_manager()
        db.store_all(word, host_ip, 'ip', 'DNS-resolver')

    if trello_info[1] is True:
        trello_urls = trello_info[0]
        if trello_urls is []:
            print('\n[*] No URLs found.')
        else:
            total = len(trello_urls)
            print('\n[*] URLs found: ' + str(total))
            print('--------------------')
            for url in sorted(list(set(trello_urls))):
                print(url)

    # DNS brute force
    dnsres = []
    if dnsbrute is True:
        print('\n[*] Starting DNS brute force.')
        a = dnssearch.dns_force(word, dnsserver, verbose=True)
        res = a.process()
        print('\n[*] Hosts found after DNS brute force:')
        print('-------------------------------------')
        for y in res:
            print(y)
            dnsres.append(y.split(':')[0])
            if y not in full:
                full.append(y)
        db = stash.stash_manager()
        db.store_all(word, dnsres, 'host', 'dns_bruteforce')

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
                        search_take = takeover.take_over(domain)
                        search_take.process()
                except Exception as e:
                    print(e)

    # DNS reverse lookup
    dnsrev = []
    if dnslookup is True:
        print('\n[*] Starting active queries.')
        analyzed_ranges = []
        for x in host_ip:
            print(x)
            ip = x.split(':')[0]
            range = ip.split('.')
            range[3] = '0/24'
            s = '.'
            range = s.join(range)
            if not analyzed_ranges.count(range):
                print('[*] Performing reverse lookup in ' + range)
                a = dnssearch.dns_reverse(range, True)
                a.list()
                res = a.process()
                analyzed_ranges.append(range)
            else:
                continue
            for x in res:
                if x.count(word):
                    dnsrev.append(x)
                    if x not in full:
                        full.append(x)
        print('[*] Hosts found after reverse lookup (in target domain):')
        print('--------------------------------------------------------')
        for xh in dnsrev:
            print(xh)

    # DNS TLD expansion
    dnstldres = []
    if dnstld is True:
        print('[*] Starting DNS TLD expansion.')
        a = dnssearch.dns_tld(word, dnsserver, verbose=True)
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
            search = bingsearch.SearchBing(l, limit, start)
            search.process_vhost()
            res = search.get_allhostnames()
            for x in res:
                x = re.sub(r'[[\<\/?]*[\w]*>]*', '', x)
                x = re.sub('<', '', x)
                x = re.sub('>', '', x)
                print((l + '\t' + x))
                vhost.append(l + ':' + x)
                full.append(l + ':' + x)
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
        host_ip = list(set(host_ip))
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
    recursion = None
    if recursion:
        counter = 0
        for word in vhost:
            search = googlesearch.search_google(word, limit, counter)
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
            db = stash.stash_manager()
            scanboarddata = db.getscanboarddata()
            latestscanresults = db.getlatestscanresults(word)
            previousscanresults = db.getlatestscanresults(word, previousday=True)
            latestscanchartdata = db.latestscanchartdata(word)
            scanhistorydomain = db.getscanhistorydomain(word)
            pluginscanstatistics = db.getpluginscanstatistics()
            generator = statichtmlgenerator.htmlgenerator(word)
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
            Html_file = open('report.html', 'w')
            Html_file.write(HTMLcode)
            Html_file.close()
            print('[*] Reporting finished.')
            print('[*] Saving files.')
            html = htmlExport.htmlExport(
                all_emails,
                full,
                vhost,
                dnsres,
                dnsrev,
                filename,
                word,
                shodanres,
                dnstldres)
            html.writehtml()
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
                    if temp != []:
                        shodanalysis.append(res[0] + ':' + temp[0])
                    file.write('</shodan>')
                if shodanalysis != []:
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
    if python_version()[0:3] < '3.6':
        print('\033[93m[!] Make sure you have Python 3.6+ installed, quitting.\n\n \033[0m')
        sys.exit(1)
    try:
        start()
    except KeyboardInterrupt:
        print('\n\n\033[93m[!] ctrl+c detected from user, quitting.\n\n \033[0m')
    except Exception:
        import traceback

        print(traceback.print_exc())
        sys.exit(1)


if __name__ == '__main__':
    entry_point()
