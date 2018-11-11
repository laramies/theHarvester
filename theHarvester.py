#!/usr/bin/env python

import string
import httplib
import sys
import os
from socket import *
import re
import getopt
import stash
import time

try:
    import requests
except:
    print "Request library not found, please install it before proceeding\n"
    sys.exit()

from discovery import *
from lib import htmlExport
from lib import hostchecker

print "\n \033[92m *******************************************************************"
print "*                                                                 *"
print "* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *"
print "* | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *"
print "* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *"
print "*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *"
print "*                                                                 *"
print "* TheHarvester Ver. 3.0.0                                         *"
print "* Coded by Christian Martorella                                   *"
print "* Edge-Security Research                                          *"
print "* cmartorella@edge-security.com                                   *"
print "*******************************************************************\033[94m\n\n"


def usage():

    comm = os.path.basename(sys.argv[0])

    if os.path.dirname(sys.argv[0]) == os.getcwd():
        comm = "./" + comm

    print "Usage: theharvester options \n"
    print "       -d: Domain to search or company name"
    print """       -b: data source: baidu, bing, bingapi, dogpile, google, googleCSE,
                        googleplus, google-profiles, linkedin, pgp, twitter, vhost, 
                        virustotal, threatcrowd, crtsh, netcraft, yahoo, hunter, all\n"""
    print "       -g: use google dorking instead of normal google search"
    print "       -s: start in result number X (default: 0)"
    print "       -v: verify host name via dns resolution and search for virtual hosts"
    print "       -f: save the results into an HTML and XML file (both)"
    print "       -n: perform a DNS reverse query on all ranges discovered"
    print "       -c: perform a DNS brute force for the domain name"
    print "       -t: perform a DNS TLD expansion discovery"
    print "       -e: use this DNS server"
    print "       -p: port scan the detected hosts and check for Takeovers (80,443,22,21,8080)"
    print "       -l: limit the number of results to work with(bing goes from 50 to 50 results,"
    print "            google 100 to 100, and pgp doesn't use this option)"
    print "       -h: use SHODAN database to query discovered hosts"
    print "\nExamples:"
    print "        " + comm + " -d microsoft.com -l 500 -b google -h myresults.html"
    print "        " + comm + " -d microsoft.com -b pgp"
    print "        " + comm + " -d microsoft -l 200 -b linkedin"
    print "        " + comm + " -d microsoft.com -l 200 -g -b google"
    print "        " + comm + " -d apple.com -b googleCSE -l 500 -s 300\n"


def start(argv):
    if len(sys.argv) < 4:
        usage()
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, "l:d:b:s:u:vf:nhcgpte:")
    except getopt.GetoptError:
        usage()
        sys.exit()
    try:
        db=stash.stash_manager()
        db.do_init()
    except Exception, e:
        pass
    start = 0
    host_ip = []
    filename = ""
    bingapi = "yes"
    dnslookup = False
    dnsbrute = False
    dnstld = False
    shodan = False
    vhost = []
    virtual = False
    ports_scanning = False
    takeover_check = False
    google_dorking = False
    limit = 500
    dnsserver = ""
    for opt, arg in opts:
        if opt == '-l':
            limit = int(arg)
        elif opt == '-d':
            word = arg
        elif opt == '-g':
            google_dorking = True
        elif opt == '-s':
            start = int(arg)
        elif opt == '-v':
            virtual = "basic"
        elif opt == '-f':
            filename = arg
        elif opt == '-n':
            dnslookup = True
        elif opt == '-c':
            dnsbrute = True
        elif opt == '-h':
            shodan = True
        elif opt == '-e':
            dnsserver = arg
        elif opt == '-p':
            ports_scanning = True
        elif opt == '-t':
            dnstld = True
        elif opt == '-b':
            engines = set(arg.split(','))
            supportedengines = set(["baidu","bing","crtsh","bingapi","dogpile","google","googleCSE","virustotal","threatcrowd","googleplus","google-profiles","linkedin","pgp","twitter","vhost","yahoo","netcraft","hunter","all"])
            if set(engines).issubset(supportedengines):
                print "found supported engines"
                print "[-] Starting harvesting process for domain: " + word +  "\n" 
                for engineitem in engines:
                    if engineitem == "google":
                        print "[-] Searching in Google:"
                        search = googlesearch.search_google(word, limit, start)
                        search.process(google_dorking)
                        all_emails = search.get_emails()
                        all_hosts = search.get_hostnames()
                        for x in all_hosts:
                            try:
                                db=stash.stash_manager()
                                db.store(word,x,'host','google')
                            except Exception, e:
                                print e
                    
                    if engineitem == "netcraft":
                        print "[-] Searching in Netcraft:"
                        search = netcraft.search_netcraft(word)
                        search.process()
                        all_hosts = search.get_hostnames()
                        all_emails = []
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','netcraft')
                        
                    
                    if engineitem == "threatcrowd":
                        print "[-] Searching in Threatcrowd:"
                        search = threatcrowd.search_threatcrowd(word)
                        search.process()
                        all_hosts = search.get_hostnames()
                        all_emails = []
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','threatcrowd')
                
                    if engineitem == "virustotal":
                        print "[-] Searching in Virustotal:"
                        search = virustotal.search_virustotal(word)
                        search.process()
                        all_hosts = search.get_hostnames()
                        all_emails = []
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','virustotal')
                

                    if engineitem == "crtsh":
                        print "[-] Searching in CRT.sh:"
                        search = crtsh.search_crtsh(word)
                        search.process()
                        all_hosts = search.get_hostnames()
                        all_emails = []
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','CRTsh')

                    if engineitem == "googleCSE":
                        print "[-] Searching in Google Custom Search:"
                        search = googleCSE.search_googleCSE(word, limit, start)
                        search.process()
                        search.store_results()
                        all_emails = search.get_emails()
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'email','googleCSE')
                        all_hosts = search.get_hostnames()
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','googleCSE')

                    elif engineitem == "bing" or engineitem == "bingapi":
                        print "[-] Searching in Bing:"
                        search = bingsearch.search_bing(word, limit, start)
                        if engineitem == "bingapi":
                            bingapi = "yes"
                        else:
                            bingapi = "no"
                        search.process(bingapi)
                        all_emails = search.get_emails()
                        all_hosts = search.get_hostnames()

                    elif engineitem == "dogpile":
                        print "[-] Searching in Dogpilesearch.."
                        search = dogpilesearch.search_dogpile(word, limit)
                        search.process()
                        all_emails = search.get_emails()
                        all_hosts = search.get_hostnames()

                    elif engineitem == "pgp":
                        print "[-] Searching in PGP key server.."
                        search = pgpsearch.search_pgp(word)
                        search.process()
                        all_emails = search.get_emails()
                        all_hosts = search.get_hostnames()
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','pgp')
                        db=stash.stash_manager()
                        db.store_all(word,all_emails,'emails','pgp')

                    elif engineitem == "yahoo":
                        print "[-] Searching in Yahoo.."
                        search = yahoosearch.search_yahoo(word, limit)
                        search.process()
                        all_emails = search.get_emails()
                        all_hosts = search.get_hostnames()

                   # elif engineitem == "baidu":
                        print "[-] Searching in Baidu.."
                        search = baidusearch.search_baidu(word, limit)
                        search.process()
                        all_emails = search.get_emails()
                        all_hosts = search.get_hostnames()

                    elif engineitem == "googleplus":
                        print "[-] Searching in Google+ .."
                        search = googleplussearch.search_googleplus(word, limit)
                        search.process()
                        people = search.get_people()
                        print "Users from Google+:"
                        print "===================="
                        for user in people:
                            print user
                        sys.exit()

                    elif engineitem == "twitter":
                        print "[-] Searching in Twitter .."
                        search = twittersearch.search_twitter(word, limit)
                        search.process()
                        people = search.get_people()
                        print "Users from Twitter:"
                        print "-------------------"
                        for user in people:
                            print user
                        sys.exit()

                    elif engineitem == "linkedin":
                        print "[-] Searching in Linkedin.."
                        search = linkedinsearch.search_linkedin(word, limit)
                        search.process()
                        people = search.get_people()
                        print "Users from Linkedin:"
                        print "-------------------"
                        for user in people:
                            print user
                        sys.exit()

                    elif engineitem == "google-profiles":
                        print "[-] Searching in Google profiles.."
                        search = googlesearch.search_google(word, limit, start)
                        search.process_profiles()
                        people = search.get_profiles()
                        print "Users from Google profiles:"
                        print "---------------------------"
                        for users in people:
                            print users
                        sys.exit()

                    elif engineitem == "hunter":
                        print "[-] Searching in Hunter:"
                        from discovery import huntersearch
                        #import locally or won't work
                        search = huntersearch.search_hunter(word, limit, start)
                        search.process()
                        all_emails = search.get_emails()
                        all_hosts = search.get_hostnames()

                    elif engineitem == "all":
                        print "Full harvest on " + word
                        all_emails = []
                        all_hosts = []
                    
                        print "[-] Searching in Google.."
                        search = googlesearch.search_google(word, limit, start)
                        search.process(google_dorking)
                        emails = search.get_emails()
                        hosts = search.get_hostnames()
                        all_emails.extend(emails)
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'email','google')
                        all_hosts.extend(hosts)
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','google')
                        
                        print "[-] Searching in PGP Key server.."
                        search = pgpsearch.search_pgp(word)
                        search.process()
                        emails = search.get_emails()
                        hosts = search.get_hostnames()
                        all_hosts.extend(hosts)
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','PGP')
                        all_emails.extend(emails)
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'email','PGP')
                        
                        print "[-] Searching in Netcraft server.."
                        search = netcraft.search_netcraft(word)
                        search.process()
                        hosts = search.get_hostnames()
                        all_hosts.extend(hosts)
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','netcraft')

                        print "[-] Searching in ThreatCrowd server.."
                        try:
                            search = threatcrowd.search_threatcrowd(word)
                            search.process()
                            hosts = search.get_hostnames()
                            all_hosts.extend(hosts)
                            all_emails = []
                            db=stash.stash_manager()
                            db.store_all(word,all_hosts,'host','threatcrowd')
                        except Exception: pass

                        print "[-] Searching in CRTSH server.."
                        search = crtsh.search_crtsh(word)
                        search.process()
                        hosts = search.get_hostnames()
                        all_hosts.extend(hosts)
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','CRTsh')

                        print "[-] Searching in Virustotal server.."
                        search = virustotal.search_virustotal(word)
                        search.process()
                        hosts = search.get_hostnames()
                        all_hosts.extend(hosts)
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','virustotal')

                        print "[-] Searching in Bing.."
                        bingapi = "no"
                        search = bingsearch.search_bing(word, limit, start)
                        search.process(bingapi)
                        emails = search.get_emails()
                        hosts = search.get_hostnames()
                        all_hosts.extend(hosts)
                        db=stash.stash_manager()
                        db.store_all(word,all_hosts,'host','bing')
                        all_emails.extend(emails)
                        #Clean up email list, sort and uniq
                        all_emails=sorted(set(all_emails))

                        print "[-] Searching in Hunter:"
                        from discovery import huntersearch
                        #import locally
                        search = huntersearch.search_hunter(word, limit, start)
                        search.process()
                        emails = search.get_emails()
                        hosts = search.get_hostnames()
                        all_hosts.extend(hosts)
                        db = stash.stash_manager()
                        db.store_all(word, all_hosts, 'host', 'hunter')
                        all_emails.extend(emails)
                        all_emails = sorted(set(all_emails))

            else:
            #if engine not in ("baidu", "bing", "crtsh","bingapi","dogpile","google", "googleCSE","virustotal","threatcrowd", "googleplus", "google-profiles","linkedin", "pgp", "twitter", "vhost", "yahoo","netcraft","all"):
                usage()
                print "Invalid search engine, try with: baidu, bing, bingapi, crtsh, dogpile, google, googleCSE, virustotal, netcraft, googleplus, google-profiles, linkedin, pgp, twitter, vhost, yahoo, hunter, all"
                sys.exit()
            #else:
            #    pass

    #Results############################################################
    print("\n\033[1;32;40m Harvesting results")
    print "\n\n[+] Emails found:"
    print "------------------"
    if all_emails == []:
        print "No emails found"
    else:
        print "\n".join(all_emails)

    print("\033[1;33;40m \n[+] Hosts found in search engines:")
    print "------------------------------------"
    if all_hosts == []:
        print "No hosts found"
        full = ""
    else:
        total = len(all_hosts)
        print "\nTotal hosts: " + str(total) + "\n"
        all_hosts=sorted(set(all_hosts))
        print "\033[94m[-] Resolving hostnames IPs...\033[1;33;40m \n "
        full_host = hostchecker.Checker(all_hosts)
        full = full_host.check()
        for host in full:
            ip = host.split(':')[1]
            print host
            if ip != "empty":
                if host_ip.count(ip.lower()):
                    pass
                else:
                    host_ip.append(ip.lower())

    #DNS Brute force####################################################
    dnsres = []
    if dnsbrute == True:
        print "\n\033[94m[-] Starting DNS brute force: \033[1;33;40m"
        a = dnssearch.dns_force(word, dnsserver, verbose=True)
        res = a.process()
        print "\n\033[94m[-] Hosts found after DNS brute force:"
        print "---------------------------------------"
        for y in res:
            print y
            dnsres.append(y.split(':')[0])
            if y not in full:
                full.append(y)
        db=stash.stash_manager()
        db.store_all(word,dnsres,'host','dns_bruteforce')

    #Port Scanning #################################################
    if ports_scanning == True:
            print("\n\n\033[1;32;40m[-] Scanning ports (active):\n")
            for x in full:
                host = x.split(':')[1]
                domain = x.split(':')[0]
                if host != "empty" :
                    print "- Scanning : " + host
                    ports = [80,443,22,8080,21]
                    try:
                        scan = port_scanner.port_scan(host,ports)
                        openports = scan.process()
                        if len(openports) > 1:
                                print "\t\033[91m Detected open ports: " + ','.join(str(e) for e in openports) +  "\033[1;32;40m"
                        takeover_check = 'True'
                        if takeover_check == 'True':
                            if len(openports) > 0:   
                                search_take = takeover.take_over(domain)
                                search_take.process()
                    except Exception, e:
                        print e
                    

    #DNS reverse lookup#################################################
    dnsrev = []
    if dnslookup == True:
        print "\n[+] Starting active queries:"
        analyzed_ranges = []
        for x in host_ip:
            print x
            ip = x.split(":")[0]
            range = ip.split(".")
            range[3] = "0/24"
            range = string.join(range, '.')
            if not analyzed_ranges.count(range):
                print "\033[94m[-]Performing reverse lookup in : " + range + "\033[1;33;40m"
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
        print "Hosts found after reverse lookup (in target domain):"
        print "---------------------------------"
        for xh in dnsrev:
            print xh
        
    #DNS TLD expansion###################################################
    dnstldres = []
    if dnstld == True:
        print "[-] Starting DNS TLD expansion:"
        a = dnssearch.dns_tld(word, dnsserver, verbose=True)
        res = a.process()
        print "\n[+] Hosts found after DNS TLD expansion:"
        print "------------------------------------------"
        for y in res:
            print y
            dnstldres.append(y)
            if y not in full:
                full.append(y)

    #Virtual hosts search###############################################
    if virtual == "basic":
        print "\n[+] Virtual hosts:"
        print "------------------"
        for l in host_ip:
            search = bingsearch.search_bing(l, limit, start)
            search.process_vhost()
            res = search.get_allhostnames()
            for x in res:
                x = re.sub(r'[[\<\/?]*[\w]*>]*','',x)
                x = re.sub('<','',x)
                x = re.sub('>','',x)
                print l + "\t" + x
                vhost.append(l + ":" + x)
                full.append(l + ":" + x)
        vhost=sorted(set(vhost))
    else:
        pass
    #Shodan search####################################################
    shodanres = []
    shodanvisited = []
    if shodan == True:
        print("\n\n\033[1;32;40m[-] Shodan DB search (passive):\n")
        for x in full:
            try:
                ip = x.split(":")[1]
                if not shodanvisited.count(ip):
                    print "\tSearching for: " + ip
                    a = shodansearch.search_shodan(ip)
                    shodanvisited.append(ip)
                    results = a.run()
                    time.sleep(2)
                    for res in results:
                        if res['info'] == []:
                            res['info'] = ''
                        shodanres.append(
                            x + "SAPO" + str(res['info']) + "SAPO" + str(res['data']))
            except:
                pass
        print "\n [+] Shodan results:"
        print "------------------"
        for x in shodanres:
            print x.split("SAPO")[0] + ":" + x.split("SAPO")[1]
    else:
        pass

    ###################################################################
    # Here i need to add explosion mode.
    # Tengo que sacar los TLD para hacer esto.
    recursion = None
    if recursion:
        start = 0
        for word in vhost:
            search = googlesearch.search_google(word, limit, start)
            search.process(google_dorking)
            emails = search.get_emails()
            hosts = search.get_hostnames()
            print emails
            print hosts
    else:
        pass

    #Reporting#######################################################
    if filename != "":
        try:
            print "[+] Saving files..."
            filename = filename.split(".")[0] + ".html"
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
            save = html.writehtml()
        except Exception as e:
            print e
            print "Error creating the file"
        try:
            filename = filename.split(".")[0] + ".xml"
            file = open(filename, 'w')
            file.write('<?xml version="1.0" encoding="UTF-8"?><theHarvester>')
            for x in all_emails:
                file.write('<email>' + x + '</email>')

            for x in full:
                x = x.split(":")
                if len(x) == 2:
                    file.write('<host>' + '<ip>' + x[0] + '</ip><hostname>' + x[1]  + '</hostname>' + '</host>')
                else:
                    file.write('<host>' + x + '</host>')
            for x in vhost:
                x = x.split(":")
                if len(x) == 2:
                    file.write('<vhost>' + '<ip>' + x[0] + '</ip><hostname>' + x[1]  + '</hostname>' + '</vhost>')
                else:
                    file.write('<vhost>' + x + '</vhost>')

            if shodanres != []:
                shodanalysis = []
                for x in shodanres:
                    res = x.split("SAPO")
                    # print " res[0] " + res[0] # ip/host
                    # print " res[1] " + res[1] # banner/info
                    # print " res[2] " + res[2] # port
                    file.write('<shodan>')
                    #page.h3(res[0])
                    file.write('<host>' + res[0] + '</host>')
                    #page.a("Port :" + res[2])
                    file.write('<port>' + res[2] + '</port>')
                    #page.pre(res[1])
                    file.write('<banner><!--' + res[1] + '--></banner>')
                    
                    
                    reg_server = re.compile('Server:.*')
                    temp = reg_server.findall(res[1])
                    if temp != []:
                        shodanalysis.append(res[0] + ":" + temp[0])
                    
                    file.write('</shodan>')
                if shodanalysis != []:
                    shodanalysis=sorted(set(shodanalysis))
                    file.write('<servers>')
                    for x in shodanalysis:
                        #page.pre(x)
                        file.write('<server>' + x + '</server>')
                    file.write('</servers>')
                    

            file.write('</theHarvester>')
            file.flush()
            file.close()
            print "Files saved!"
        except Exception as er:
            print "Error saving XML file: " + er
        sys.exit()

if __name__ == "__main__":
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print "Search interrupted by user.."
    except:
        sys.exit()
