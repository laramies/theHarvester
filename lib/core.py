# coding=utf-8

import os
import sys

class Core:
    @staticmethod
    def banner():
        print("\n\033[92m*******************************************************************")
        print("*                                                                 *")
        print("* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *")
        print("* | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *")
        print("* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *")
        print("*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *")
        print("*                                                                 *")
        print("* theHarvester 3.0.6 v111                                         *")
        print("* Coded by Christian Martorella                                   *")
        print("* Edge-Security Research                                          *")
        print("* cmartorella@edge-security.com                                   *")
        print("*******************************************************************\033[94m\n\n")

    @staticmethod
    def usage():
        comm = os.path.basename(sys.argv[0])

        if os.path.dirname(sys.argv[0]) == os.getcwd():
            comm = "./" + comm

        print("Usage: theHarvester.py <options> \n")
        print("   -d: company name or domain to search")
        print("""   -b: source: baidu, bing, bingapi, censys, crtsh, cymon, dogpile, google,
                   googleCSE, googleplus, google-certificates, google-profiles,
                   hunter, linkedin, netcraft, pgp, securityTrails, threatcrowd,
                   trello, twitter, vhost, virustotal, yahoo, all""")
        print("   -g: use Google Dorking instead of normal Google search")
        print("   -s: start with result number X (default: 0)")
        print("   -v: verify host name via DNS resolution and search for virtual hosts")
        print("   -f: save the results into an HTML and/or XML file")
        print("   -n: perform a DNS reverse query on all ranges discovered")
        print("   -c: perform a DNS brute force on the domain")
        print("   -t: perform a DNS TLD expansion discovery")
        print("   -e: specify DNS server")
        print("   -p: port scan the detected hosts and check for Takeovers (21,22,80,443,8080)")
        print("   -l: limit the number of results (Bing goes from 50 to 50 results,")
        print("       Google 100 to 100, and PGP doesn't use this option)")
        print("   -h: use Shodan to query discovered hosts")
        print("\nExamples:")
        print(("       " + comm + " -d acme.com -l 500 -b google -f myresults.html"))
        print(("       " + comm + " -d acme.com -b pgp, virustotal"))
        print(("       " + comm + " -d acme -l 200 -b linkedin"))
        print(("       " + comm + " -d acme.com -l 200 -g -b google"))
        print(("       " + comm + " -d acme.com -b googleCSE -l 500 -s 300"))
        print(("       " + comm + " -d acme.edu -l 100 -b bing -h \n"))
