#!/usr/bin/env python

import string
import httplib, sys
from socket import *
import re
import getopt
from discovery import *
import hostchecker


print "\n*************************************"
print "*TheHarvester Ver. 2.0 (reborn)     *"
print "*Coded by Christian Martorella      *"
print "*Edge-Security Research             *"
print "*cmartorella@edge-security.com      *"
print "*************************************\n\n"

def usage():

 print "Usage: theharvester options \n"
 print "       -d: Domain to search or company name"
 print "       -b: Data source (google,bing,bingapi,pgp,linkedin,google-profiles,exalead,all)"
 print "       -s: Start in result number X (default 0)"
 print "       -v: Verify host name via dns resolution and search for vhosts(basic)"
 print "       -l: Limit the number of results to work with(bing goes from 50 to 50 results,"
 print "            google 100 to 100, and pgp does'nt use this option)"
 print "       -f: Save the results into an XML file"
 print "\nExamples:./theharvester.py -d microsoft.com -l 500 -b google"
 print "         ./theharvester.py -d microsoft.com -b pgp"
 print "         ./theharvester.py -d microsoft -l 200 -b linkedin\n"


def start(argv):
	if len(sys.argv) < 4:
		usage()
		sys.exit()
	try :
	       opts, args = getopt.getopt(argv, "l:d:b:s:v:f:")
	except getopt.GetoptError:
  	     	usage()
		sys.exit()
	start=0
	host_ip=[]
	filename=""
	bingapi="yes"
	start=0
	for opt, arg in opts:
		if opt == '-l' :
			limit = int(arg)
		elif opt == '-d':
			word = arg	
		elif opt == '-s':
			start = int(arg)
		elif opt == '-v':
			virtual = arg
		elif opt == '-f':
			filename= arg
		elif opt == '-b':
			engine = arg
			if engine not in ("google", "linkedin", "pgp", "all","google-profiles","exalead","bing","bing_api","yandex"):
				usage()
				print "Invalid search engine, try with: bing, google, linkedin, pgp"
				sys.exit()
			else:
				pass
	if engine == "google":
		print "[-] Searching in Google:"
		search=googlesearch.search_google(word,limit,start)
		search.process()
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	if engine == "exalead":
		print "[-] Searching in Exalead:"
		search=exaleadsearch.search_exalead(word,limit,start)
		search.process()
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	elif engine == "bing" or engine =="bingapi":	
		print "[-] Searching in Bing:"
		search=bingsearch.search_bing(word,limit,start)
		if engine =="bingapi":
			bingapi="yes"
		else:
			bingapi="no"
		search.process(bingapi)
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	elif engine == "yandex":# Not working yet
		print "[-] Searching in Yandex:"
		search=yandexsearch.search_yandex(word,limit,start)
		search.process()
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	elif engine == "pgp":
		print "[-] Searching in PGP key server.."
		search=pgpsearch.search_pgp(word)
		search.process()
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	elif engine == "linkedin":
		print "[-] Searching in Linkedin.."
		search=linkedinsearch.search_linkedin(word,limit)
		search.process()
		people=search.get_people()
		print "Users from Linkedin:"
		print "===================="
		for user in people:
			print user
		sys.exit()
	elif engine == "google-profiles":
		print "[-] Searching in Google profiles.."
		search=googlesearch.search_google(word,limit,start)
		search.process_profiles()
		people=search.get_profiles()
		print "Users from Google profiles:"
		print "---------------------------"
		for users in people:
			print users
		sys.exit()
	elif engine == "all":
		print "Full harvest.."
		all_emails=[]
		all_hosts=[]
		virtual = "basic"
		print "[-] Searching in Google.."
		search=googlesearch.search_google(word,limit,start)
		search.process()
		emails=search.get_emails()
		hosts=search.get_hostnames()
		all_emails.extend(emails)
		all_hosts.extend(hosts)
		print "[-] Searching in PGP Key server.."
		search=pgpsearch.search_pgp(word)
		search.process()
		emails=search.get_emails()
		hosts=search.get_hostnames()
		all_hosts.extend(hosts)
		all_emails.extend(emails)
		print "[-] Searching in Bing.."
		bingapi="yes"
		search=bingsearch.search_bing(word,limit,start)
		search.process(bingapi)
		emails=search.get_emails()
		hosts=search.get_hostnames()
		all_hosts.extend(hosts)
		all_emails.extend(emails)
		print "[-] Searching in Exalead.."
		search=exaleadsearch.search_exalead(word,limit,start)
		search.process()
		emails=search.get_emails()
		hosts=search.get_hostnames()
		all_hosts.extend(hosts)
		all_emails.extend(emails)

	print "\n[+] Emails found:"
	print " -------------"
	if all_emails ==[]:
		print "No emails found"
	else:
		for emails in all_emails:
			print emails 
	print "\n[+] Hosts found"
	print " -----------"
	if all_hosts == []:
		print "No hosts found"
	else:
		full_host=hostchecker.Checker(all_hosts)
		full=full_host.check()
		vhost=[]
		for host in full:
			print host
			ip=host.split(':')[0]
			if host_ip.count(ip.lower()):
				pass
			else:
				host_ip.append(ip.lower())
	if virtual == "basic":
		print "[+] Virtual hosts:"
		print "----------------"
		for l in host_ip:
			search=bingsearch.search_bing(l,limit,start)
 			search.process_vhost()
 			res=search.get_allhostnames()
			for x in res:
				print l+":"+x
				vhost.append(l+":"+x)
				full.append(l+":"+x)
	else:
		pass #Here i need to add explosion mode.
	#Tengo que sacar los TLD para hacer esto.
	recursion=None	
	if recursion:
		limit=300
		start=0
		for word in vhost:
			search=googlesearch.search_google(word,limit,start)
			search.process()
			emails=search.get_emails()
			hosts=search.get_hostnames()
			print emails
			print hosts
	else:
		pass
	if filename!="":
		file = open(filename,'w')
		file.write('<theHarvester>')
		for x in all_emails:
			file.write('<email>'+x+'</email>')
		for x in all_hosts:
			file.write('<host>'+x+'</host>')
		for x in vhosts:
			file.write('<vhost>'+x+'</vhost>')
		file.write('</theHarvester>')
		file.close
		print "Results saved in: "+ filename
	else:
		pass

		
if __name__ == "__main__":
        try: start(sys.argv[1:])
	except KeyboardInterrupt:
		print "Search interrupted by user.."
	except:
		sys.exit()

