![theHarvester](https://github.com/laramies/theHarvester/blob/master/theHarvester-logo.webp)

![TheHarvester CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Python%20CI/badge.svg) ![TheHarvester Docker Image CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Docker%20Image%20CI/badge.svg)
[![Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/img/badges/Rawsec-inventoried-FF5050_flat_without_logo.svg)](https://inventory.raw.pm/)

What is this?
-------------
theHarvester is a simple to use, yet powerful tool designed to be used during the reconnaissance stage of a red<br>
team assessment or penetration test. It performs open source intelligence (OSINT) gathering to help determine<br>
a domain's external threat landscape. The tool gathers names, emails, IPs, subdomains, and URLs by using<br>
multiple public resources that include:<br>

Passive:
--------
* anubis: Anubis-DB - https://github.com/jonluca/anubis

* bevigil: CloudSEK BeVigil scans mobile application for OSINT assets and makes them available through an API - https://bevigil.com/osint-api

* baidu: Baidu search engine - www.baidu.com

* binaryedge: List of known subdomains from www.binaryedge.io

* bing: Microsoft search engine - www.bing.com

* bingapi: Microsoft search engine, through the API (Requires an API key, see below.)

* brave: Brave search engine - https://search.brave.com/

* bufferoverun: https://tls.bufferover.run

* censys: [Censys search engine](https://search.censys.io/), will use certificates searches to enumerate subdomains and gather emails (Requires an API key, see below.) - [censys.io](https://censys.io/)

* certspotter: Cert Spotter monitors Certificate Transparency logs - https://sslmate.com/certspotter/

* criminalip Specialized Cyber Threat Intelligence (CTI) search engine - https://www.criminalip.io

* crtsh: Comodo Certificate search - https://crt.sh

* dnsdumpster: DNSdumpster search engine - https://dnsdumpster.com

* duckduckgo: DuckDuckGo search engine - www.duckduckgo.com

* fullhunt: The Next-Generation Attack Surface Security Platform - https://fullhunt.io

* github-code: GitHub code search engine (Requires a GitHub Personal Access Token, see below.) - www.github.com

* hackertarget: Online vulnerability scanners and network intelligence to help organizations - https://hackertarget.com

* hunter: Hunter search engine (Requires an API key, see below.) - www.hunter.io

* hunterhow: Internet Search Engines For Security Researchers - https://hunter.how

* intelx: Intelx search engine (Requires an API key, see below.) - www.intelx.io

* Netlas: A Shodan or Censys competitor - https://app.netlas.io

* otx: AlienVault Open Threat Exchange - https://otx.alienvault.com

* Pentest-Tools.com: Cloud-based toolkit for offensive security testing, focused on web applications and network penetration testing (Requires an API key, see below.) - https://pentest-tools.com/

* projecdiscovery: We actively collect and maintain internet-wide assets data,
  to enhance research and analyse changes around DNS for better insights (Requires an API key, see below.) - https://chaos.projectdiscovery.io

* rapiddns: DNS query tool which make querying subdomains or sites of a same IP easy! https://rapiddns.io

* rocketreach: Access real-time verified personal/professional emails, phone numbers, and social media links. - https://rocketreach.co

* securityTrails: Security Trails search engine, the world's largest repository of historical DNS data<br>
  (Requires an API key, see below.) - www.securitytrails.com

* shodan: Shodan search engine, will search for ports and banners from discovered hosts (Requires an API key, see below.) - https://shodan.io

* sitedossier: Find available information on a site

* subdomainfinderc99: A subdomain finder is a tool used to find the subdomains of a given domain - https://subdomainfinder.c99.nl

* threatminer: Data mining for threat intelligence - https://www.threatminer.org/

* urlscan: A sandbox for the web that is a URL and website scanner - https://urlscan.io

* vhost: Bing virtual hosts search

* virustotal: virustotal.com domain search

* yahoo: Yahoo search engine

* zoomeye: China version of shodan - https://www.zoomeye.org


Active:
-------
* DNS brute force: dictionary brute force enumeration
* Screenshots: Take screenshots of subdomains that were found

Modules that require an API keys:
--------------------------------
Documentation to setup API keys can be found at - https://github.com/laramies/theHarvester/wiki/Installation#api-keys

* bevigil - Free upto 50 queries. Pricing can be found here: https://bevigil.com/pricing/osint
* binaryedge - $10/month
* bing
* bufferoverun - uses the free api
* censys - API keys are required and can be retrieved from your [Censys account](https://search.censys.io/account/api).
* criminalip
* fullhunt
* github
* hunter - limited to 10 on the free plan, so you will need to do -l 10 switch
* hunterhow
* intelx
* netlas - $
* pentesttools - $
* projecdiscovery - invite only for now
* rocketreach - $
* securityTrails
* shodan - $
* zoomeye

Install and dependencies:
-------------------------
* Python 3.9+
* https://github.com/laramies/theHarvester/wiki/Installation


Comments, bugs, and requests:
-----------------------------
* [![Twitter Follow](https://img.shields.io/twitter/follow/laramies.svg?style=social&label=Follow)](https://twitter.com/laramies) Christian Martorella @laramies
  cmartorella@edge-security.com
* [![Twitter Follow](https://img.shields.io/twitter/follow/NotoriousRebel1.svg?style=social&label=Follow)](https://twitter.com/NotoriousRebel1) Matthew Brown @NotoriousRebel1
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1


Main contributors:
------------------
* [![Twitter Follow](https://img.shields.io/twitter/follow/NotoriousRebel1.svg?style=social&label=Follow)](https://twitter.com/NotoriousRebel1) Matthew Brown @NotoriousRebel1
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1
* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts


Thanks:
-------
* John Matherly - Shodan project
* Ahmed Aboul Ela - subdomain names dictionaries (big and small)
