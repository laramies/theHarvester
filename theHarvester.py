#!/usr/bin/env python

import string
import httplib
import sys
import os
from socket import *
import re
import getopt

try:
    import requests
except:
    print "Request library not found, please install it before proceeding\n"
    sys.exit()

from discovery import *
from lib import htmlExport
from lib import hostchecker

print "\n*******************************************************************"
print "*                                                                 *"
print "* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *"
print "* | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *"
print "* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *"
print "*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *"
print "*                                                                 *"
print "* TheHarvester Ver. 2.7                                           *"
print "* Coded by Christian Martorella                                   *"
print "* Edge-Security Research                                          *"
print "* cmartorella@edge-security.com                                   *"
print "*******************************************************************\n\n"


def usage():

    comm = os.path.basename(sys.argv[0])

    if os.path.dirname(sys.argv[0]) == os.getcwd():
        comm = "./" + comm

    print "Usage: theharvester options \n"
    print "       -d: Domain to search or company name"
    print """       -b: data source: baidu, bing, bingapi, dogpile,google, googleCSE,
                        googleplus, google-profiles, linkedin, pgp, twitter, vhost, 
                        yahoo, all\n"""
    print "       -s: Start in result number X (default: 0)"
    print "       -v: Verify host name via dns resolution and search for virtual hosts"
    print "       -f: Save the results into an HTML and XML file (both)"
    print "       -n: Perform a DNS reverse query on all ranges discovered"
    print "       -c: Perform a DNS brute force for the domain name"
    print "       -t: Perform a DNS TLD expansion discovery"
    print "       -e: Use this DNS server"
    print "       -l: Limit the number of results to work with(bing goes from 50 to 50 results,"
    print "            google 100 to 100, and pgp doesn't use this option)"
    print "       -h: use SHODAN database to query discovered hosts"
    print "\nExamples:"
    print "        " + comm + " -d microsoft.com -l 500 -b google -h myresults.html"
    print "        " + comm + " -d microsoft.com -b pgp"
    print "        " + comm + " -d microsoft -l 200 -b linkedin"
    print "        " + comm + " -d apple.com -b googleCSE -l 500 -s 300\n"


def start(argv):
    if len(sys.argv) < 4:
        usage()
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, "l:d:b:s:vf:nhcte:")
    except getopt.GetoptError:
        usage()
        sys.exit()
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
    limit = 100
    dnsserver = ""
    for opt, arg in opts:
        if opt == '-l':
            limit = int(arg)
        elif opt == '-d':
            word = arg
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
        elif opt == '-t':
            dnstld = True
        elif opt == '-b':
            engine = arg
            if engine not in ("baidu", "bing", "bingapi","dogpile", "google", "googleCSE", "googleplus", "google-profiles","linkedin", "pgp", "twitter", "vhost", "yahoo", "all"):
                usage()
                print "Invalid search engine, try with: baidu, bing, bingapi, dogpile, google, googleCSE, googleplus, google-profiles, linkedin, pgp, twitter, vhost, yahoo, all"
                sys.exit()
            else:
                pass
    if engine == "google":
        print "[-] Searching in Google:"
        search = googlesearch.search_google(word, limit, start)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    if engine == "googleCSE":
        print "[-] Searching in Google Custom Search:"
        search = googleCSE.search_googleCSE(word, limit, start)
        search.process()
        search.store_results()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "bing" or engine == "bingapi":
        print "[-] Searching in Bing:"
        search = bingsearch.search_bing(word, limit, start)
        if engine == "bingapi":
            bingapi = "yes"
        else:
            bingapi = "no"
        search.process(bingapi)
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "dogpile":
        print "[-] Searching in Dogpilesearch.."
        search = dogpilesearch.search_dogpile(word, limit)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "pgp":
        print "[-] Searching in PGP key server.."
        search = pgpsearch.search_pgp(word)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "yahoo":
        print "[-] Searching in Yahoo.."
        search = yahoosearch.search_yahoo(word, limit)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "baidu":
        print "[-] Searching in Baidu.."
        search = baidusearch.search_baidu(word, limit)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "googleplus":
        print "[-] Searching in Google+ .."
        search = googleplussearch.search_googleplus(word, limit)
        search.process()
        people = search.get_people()
        print "Users from Google+:"
       	print "===================="
       	for user in people:
            print user
        sys.exit()

    elif engine == "twitter":
        print "[-] Searching in Twitter .."
        search = twittersearch.search_twitter(word, limit)
        search.process()
        people = search.get_people()
        print "Users from Twitter:"
       	print "===================="
       	for user in people:
            print user
        sys.exit()

    elif engine == "linkedin":
        print "[-] Searching in Linkedin.."
        search = linkedinsearch.search_linkedin(word, limit)
        search.process()
        people = search.get_people()
        print "Users from Linkedin:"
       	print "===================="
       	for user in people:
            print user
        sys.exit()
    elif engine == "google-profiles":
        print "[-] Searching in Google profiles.."
        search = googlesearch.search_google(word, limit, start)
        search.process_profiles()
        people = search.get_profiles()
        print "Users from Google profiles:"
        print "---------------------------"
        for users in people:
            print users
        sys.exit()
    elif engine == "all":
        print "Full harvest.."
        all_emails = []
        all_hosts = []
        virtual = "basic"
        print "[-] Searching in Google.."
        search = googlesearch.search_google(word, limit, start)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_emails.extend(emails)
        all_hosts.extend(hosts)
        print "[-] Searching in PGP Key server.."
        search = pgpsearch.search_pgp(word)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)
        print "[-] Searching in Bing.."
        bingapi = "no"
        search = bingsearch.search_bing(word, limit, start)
        search.process(bingapi)
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)
        print "[-] Searching in Exalead.."
        search = exaleadsearch.search_exalead(word, limit, start)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)

        #Clean up email list, sort and uniq
        all_emails=sorted(set(all_emails))
    #Results############################################################
    print "\n\n[+] Emails found:"
    print "------------------"
    if all_emails == []:
        print "No emails found"
    else:
        print "\n".join(all_emails)

    print "\n[+] Hosts found in search engines:"
    print "------------------------------------"
    if all_hosts == []:
        print "No hosts found"
    else:
        all_hosts=sorted(set(all_hosts))
        print "[-] Resolving hostnames IPs... "
        full_host = hostchecker.Checker(all_hosts)
        full = full_host.check()
        for host in full:
            ip = host.split(':')[0]
            print host
            if host_ip.count(ip.lower()):
                pass
            else:
                host_ip.append(ip.lower())

    #DNS reverse lookup#################################################
    dnsrev = []
    if dnslookup == True:
        print "\n[+] Starting active queries:"
        analyzed_ranges = []
        for x in full:
            ip = x.split(":")[0]
            range = ip.split(".")
            range[3] = "0/24"
            range = string.join(range, '.')
            if not analyzed_ranges.count(range):
                print "[-]Performing reverse lookup in :" + range
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
        print "Hosts found after reverse lookup:"
        print "---------------------------------"
        for xh in dnsrev:
            print xh
    #DNS Brute force####################################################
    dnsres = []
    if dnsbrute == True:
        print "\n[-] Starting DNS brute force:"
        a = dnssearch.dns_force(word, dnsserver, verbose=True)
        res = a.process()
        print "\n[+] Hosts found after DNS brute force:\n"
        for y in res:
            print y
            dnsres.append(y)
            if y not in full:
                full.append(y)
    #DNS TLD expansion###################################################
    dnstldres = []
    if dnstld == True:
        print "[-] Starting DNS TLD expansion:"
        a = dnssearch.dns_tld(word, dnsserver, verbose=True)
        res = a.process()
        print "\n[+] Hosts found after DNS TLD expansion:"
        print "=========================================="
        for y in res:
            print y
            dnstldres.append(y)
            if y not in full:
                full.append(y)

    #Virtual hosts search###############################################
    if virtual == "basic":
        print "[+] Virtual hosts:"
        print "=================="
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
    shodanres = []
    shodanvisited = []
    if shodan == True:
        print "[+] Shodan Database search:"
        for x in full:
            print x
            try:
                ip = x.split(":")[0]
                if not shodanvisited.count(ip):
                    print "\tSearching for: " + x
                    a = shodansearch.search_shodan(ip)
                    shodanvisited.append(ip)
                    results = a.run()
                    for res in results:
                        shodanres.append(
                            x + "SAPO" + str(res['banner']) + "SAPO" + str(res['port']))
            except:
                pass
        print "[+] Shodan results:"
        print "==================="
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
            search.process()
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
