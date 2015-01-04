#!/usr/bin/env python

from discovery import *
from lib import hostchecker
from lib import htmlExport
from socket import *
import getopt
import httplib
import os
import re
import string
import sys

os.system('clear')

print "\n*******************************************************************"
print "*                                                                 *"
print "* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *"
print "* | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *"
print "* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *"
print "*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *"
print "*                                                                 *"
print "* theHarvester v2.5                                               *"
print "* by Christian Martorella                                         *"
print "* Edge-Security Research                                          *"
print "* cmartorella@edge-security.com                                   *"
print "*                                                                 *"
print "*******************************************************************\n"

def usage():
    print """Usage: theHarvester.py <options>

Options:
    -d   Domain or company to search
    -b   Data source:
            all
            bing
            bingapi
            dogpile
            exalead
            google
            google-cse
            google-plus
            google-profiles
            jigsaw
            linkedin
            people123
            pgp
            twitter
            yandex
    -e   Specify DNS server
    -c   Perform a DNS bruteforce
    -r   Perform a DNS reverse query on all ranges discovered
    -t   Perform a DNS TLD expansion discovery
    -h   Use SHODAN to query discovered hosts
    -l   Limit the number of results
    -o   Output file (HTML and XML)
    -v   Verify host name via DNS resolution and search for virtual hosts
    -s   Start in result number x (default 0)

Examples:
    theHarvester.py -d acme.com -b google -l 500
    theHarvester.py -d acme.com -b google-cse -l 500 -s 300 \n\n"""

def start(argv):
    if len(sys.argv) < 4:
        usage()
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, "l:d:b:s:vo:rhcte:")
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
        elif opt == '-o':
            filename = arg
        elif opt == '-r':
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
            if engine not in ("all", "bing", "bingapi", "dogpile", "exalead", "google", "google-cse", "google-plus", "google-profiles", 
                              "jigsaw", "linkedin", "people123", "pgp", "twitter", "yandex"):
                usage()
                print "Invalid search engine.\n\n"
                sys.exit()
            else:
                pass
    if engine == "all":
        print "Full harvest."
        all_emails = []
        all_hosts = []
        virtual = "basic"
        print "[-] Searching Google."
        search = googlesearch.search_google(word, limit, start)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_emails.extend(emails)
        all_hosts.extend(hosts)
        print "[-] Searching PGP Key Server."
        search = pgpsearch.search_pgp(word)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)
        print "[-] Searching Bing."
        bingapi = "no"
        search = bingsearch.search_bing(word, limit, start)
        search.process(bingapi)
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)
        print "[-] Searching Exalead."
        search = exaleadsearch.search_exalead(word, limit, start)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)

    elif engine == "bing" or engine == "bingapi":
        print "[-] Searching Bing."
        search = bingsearch.search_bing(word, limit, start)
        if engine == "bingapi":
            bingapi = "yes"
        else:
            bingapi = "no"
        search.process(bingapi)
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "dogpile":
        print "[-] Searching Dogpile."
        search = dogpilesearch.search_dogpile(word, limit)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "exalead":
        print "[-] Searching Exalead."
        search = exaleadsearch.search_exalead(word, limit, start)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "google":
        print "[-] Searching Google."
        search = googlesearch.search_google(word, limit, start)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "google-cse":
        print "[-] Searching Google Custom Search."
        search = googleCSE.search_googleCSE(word, limit, start)
        search.process()
        search.store_results()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "google-plus":
        print "[-] Searching Google+."
        search = googleplussearch.search_googleplus(word, limit)
        search.process()
        people = search.get_people()
        print "Users from Google+:"
       	print "===================="
       	for user in people:
            print user
        sys.exit()

    elif engine == "google-profiles":
        print "[-] Searching Google profiles."
        search = googlesearch.search_google(word, limit, start)
        search.process_profiles()
        people = search.get_profiles()
        print "\nUsers from Google profiles:"
        print "---------------------------"
        for users in people:
            print users
        sys.exit()

    elif engine == "jigsaw":
        print "[-] Searching Jigsaw."
        search = jigsaw.search_jigsaw(word, limit)
        search.process()
        people = search.get_people()
        print "\nUsers from Jigsaw:"
        print "====================="
        for user in people:
            print user
        sys.exit()

    elif engine == "linkedin":
        print "[-] Searching Linkedin."
        search = linkedinsearch.search_linkedin(word, limit)
        search.process()
        people = search.get_people()
        print "\nUsers from Linkedin:"
       	print "===================="
       	for user in people:
            print user
        sys.exit()

    elif engine == "people123":
        print "[-] Searching 123People."
        search = people123.search_123people(word, limit)
        search.process()
        people = search.get_people()
        all_emails = search.get_emails()
        print "\nUsers from 123People:"
        print "====================="
        for user in people:
            print user

    elif engine == "pgp":
        print "[-] Searching PGP Key Server."
        search = pgpsearch.search_pgp(word)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    elif engine == "twitter":
        print "[-] Searching Twitter."
        search = twittersearch.search_twitter(word, limit)
        search.process()
        people = search.get_people()
        print "\nUsers from Twitter:"
       	print "===================="
       	for user in people:
            print user                     # Clean up and fix handle (@name remove everything after space)
        sys.exit()

    elif engine == "yandex":
        print "[-] Searching Yandex."
        search = yandexsearch.search_yandex(word, limit, start)
        search.process()
        all_emails = search.get_emails()
        all_hosts = search.get_hostnames()

    # Results ###########################################################

    print "\n\n[+] Emails found:"
    print "------------------"
    if all_emails == []:
        print "No emails found."
    else:
        for emails in all_emails:
            if emails[0] != "@":
                print emails               # Sort results

    print "\n[+] Hosts found:"
    print "------------------"
    if all_hosts == []:
        print "No hosts found.\n\n"
    else:
        full_host = hostchecker.Checker(all_hosts)
        full = full_host.check()
        for host in full:
            ip = host.split(':')[0]
            print host                     # Sort retults

            if host_ip.count(ip.lower()):
                pass
            else:
                host_ip.append(ip.lower())

    # DNS reverse lookup ################################################

    dnsrev = []
    if dnslookup == True:
        print "\n[+] Starting active queries."
        analyzed_ranges = []
        for x in full:
            ip = x.split(":")[0]
            range = ip.split(".")
            range[3] = "0/24"
            range = string.join(range, '.')
            if not analyzed_ranges.count(range):
                print "[-] Performing reverse lookup in :" + range
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

    # DNS bruteforce ####################################################

    dnsres = []
    if dnsbrute == True:
        print "\n[-] Starting DNS bruteforce."
        a = dnssearch.dns_force(word, dnsserver, verbose=True)
        res = a.process()
        print "\n[+] Hosts found after DNS bruteforce.\n"
        for y in res:
            print y
            dnsres.append(y)
            if y not in full:
                full.append(y)

    # DNS TLD expansion #################################################

    dnstldres = []
    if dnstld == True:
        print "[-] Starting DNS TLD expansion."
        a = dnssearch.dns_tld(word, dnsserver, verbose=True)
        res = a.process()
        print "\n[+] Hosts found after DNS TLD expansion:"
        print "=========================================="
        for y in res:
            print y
            dnstldres.append(y)
            if y not in full:
                full.append(y)

    # Virtual hosts search ##############################################

    if virtual == "basic":
        print "[+] Virtual hosts:"
        print "=================="
        for l in host_ip:
            search = bingsearch.search_bing(l, limit, start)
            search.process_vhost()
            res = search.get_allhostnames()
            for x in res:
                print l + "\t" + x
                vhost.append(l + ":" + x)
                full.append(l + ":" + x)
    else:
        pass
    shodanres = []
    shodanvisited = []
    if shodan == True:
        print "[+] SHODAN search."
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
        print "[+] SHODAN results:"
        print "==================="
        for x in shodanres:
            print x.split("SAPO")[0] + ":" + x.split("SAPO")[1]
    else:
        pass

    #####################################################################

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

    if filename != "":
        try:
            print "\n\n[+] Saving files."
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
            print "Error creating the file."
        try:
            filename = filename.split(".")[0] + ".xml"            # Need to add .html to one of the filenames
            file = open(filename, 'w')
            file.write('<?xml version="1.0" encoding="UTF-8"?><theHarvester>')
            for x in all_emails:
                file.write('<email>' + x + '</email>')
            for x in all_hosts:
                file.write('<host>' + x + '</host>')
            for x in vhost:
                file.write('<vhost>' + x + '</vhost>')
            file.write('</theHarvester>')
            file.close
            print "Files saved.\n\n"
        except Exception as er:
            print "Error saving XML file: " + er
        sys.exit()

if __name__ == "__main__":
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print "Search interrupted by user."
    except:
        sys.exit()

