#!/usr/bin/env python3

from theHarvester.discovery import *
from theHarvester.discovery.constants import *
from theHarvester.lib import hostchecker
from theHarvester.lib import reportgraph
from theHarvester.lib import stash
from theHarvester.lib import statichtmlgenerator
from theHarvester.lib.core import *
import argparse
import datetime
import netaddr
import re
import sys
import time

Core.banner()

supported_engines = {
    'baidu': baidusearch.SearchBaidu,
    'bing': bingsearch.SearchBing,
    'bingapi': bingsearch.SearchBing,
    'censys': censys.SearchCensys,
    'crtsh': crtsh.SearchCrtsh,
    'dnsdumpster': dnsdumpster.SearchDnsDumpster,
    'dogpile': dogpilesearch.SearchDogpile,
    'duckduckgo': duckduckgosearch.SearchDuckDuckGo,
    'exalead': exaleadsearch.SearchExalead,
    'github-code': githubcode.SearchGithubCode,
    'google': googlesearch.SearchGoogle,
    'hunter': huntersearch.SearchHunter,
    'intelx': intelxsearch.SearchIntelx,
    'linkedin': linkedinsearch.SearchLinkedin,
    'linkedin_links': linkedinsearch.SearchLinkedin,
    'netcraft': netcraft.SearchNetcraft,
    'otx': otxsearch.SearchOtx,
    'securityTrails': securitytrailssearch.SearchSecuritytrail,
    'threatcrowd': threatcrowd.SearchThreatcrowd,
    'trello': trello.SearchTrello,
    'twitter': twittersearch.SearchTwitter,
    'virustotal': virustotal.SearchVirustotal,
    'yahoo': yahoosearch.SearchYahoo,
}


def engine_is_supported(engine_name) -> bool:
    return engine_name in supported_engines

def searcher_factory(engine_name) -> type:
    """
    Factory method for creating searchers (e.g. SearchGoogle, SearchYahoo, etc.)
    """
    return supported_engines[engine_name]

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
                        dogpile, duckduckgo, github-code, google,
                        hunter, intelx,
                        linkedin, linkedin_links, netcraft, otx, securityTrails, threatcrowd,
                        trello, twitter, virustotal, yahoo''')

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
    engines = []
    filename = args.filename  # type: str
    full = []
    google_dorking = args.google_dork
    host_ip = []
    limit = args.limit  # type: int
    ports_scanning = args.port_scan
    shodan = args.shodan
    start = args.start  # type: int
    takeover_check = False
    trello_urls = []
    vhost = []
    virtual = args.virtual_host
    word = args.domain  # type: str

    if args.source is not None:
        engines = sorted(set(map(str.strip, args.source.split(','))))
        # Iterate through search engines in order
        if all(engine_is_supported(eng) for eng in engines):
            print(f'\033[94m[*] Target: {word} \n \033[0m')

            for engineitem in engines:
                search_args = [word, limit]
                if engineitem in ['bing', 'bingapi', 'exalead', 'google', 'hunter']:
                    search_args.append(start) 
                if engineitem in ['crtsh', 'dnsdumpster', 'netcraft', 'otx', 'securityTrails', 'threatcrowd', 'trello', 'virustotal']:
                    search_args.pop() 
                searcher = searcher_factory(engineitem)(*search_args)                
                Core.do_search(searcher, engineitem, db, all_hosts, all_emails, all_ip, trello_urls, google_dorking)   
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
        full = full_host.check()
        for host in full:
            host = str(host)
            print(host.lower())

        db = stash.stash_manager()
        db.store_all(word, host_ip, 'ip', 'DNS-resolver')

    length_urls = len(trello_urls)
    if length_urls == 0:
        if len(engines) >= 1 and 'trello' in engines:
            print('\n[*] No Trello URLs found.')
    else:
        total = length_urls
        print('\n[*] Trello URLs found: ' + str(total))
        print('--------------------')
        for url in sorted(trello_urls):
            print(url)

    # DNS brute force
    # dnsres = []
    if dnsbrute is True:
        print('\n[*] Starting DNS brute force.')
        a = dnssearch.DnsForce(word, dnsserver, verbose=True)
        res = a.process()
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
    recursion = False
    if recursion:
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
            db = stash.stash_manager()
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
    try:
        start()
    except KeyboardInterrupt:
        print('\n\n\033[93m[!] ctrl+c detected from user, quitting.\n\n \033[0m')
    except Exception as error_entry_point:
        print(error_entry_point)
        sys.exit(1)


if __name__ == '__main__':
    entry_point()
