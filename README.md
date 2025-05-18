![theHarvester](https://github.com/laramies/theHarvester/blob/master/theHarvester-logo.webp)

![TheHarvester CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Python%20CI/badge.svg) ![TheHarvester Docker Image CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Docker%20Image%20CI/badge.svg)
[![Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/img/badges/Rawsec-inventoried-FF5050_flat_without_logo.svg)](https://inventory.raw.pm/)

What is this?
-------------
theHarvester is a simple to use, yet powerful tool designed to be used during the reconnaissance stage of a red<br>
team assessment or penetration test. It performs open source intelligence (OSINT) gathering to help determine<br>
a domain's external threat landscape. The tool gathers names, emails, IPs, subdomains, and URLs by using<br>
multiple public resources that include:<br>

Passive modules:
----------------
* anubis: Anubis-DB - https://github.com/jonluca/anubis

* bevigil: CloudSEK BeVigil scans mobile application for OSINT assets (Requires an API key, see below.) - https://bevigil.com/osint-api

* baidu: Baidu search engine - www.baidu.com

* bing: Microsoft search engine - https://www.bing.com

* bingapi: Microsoft search engine, through the API (Requires an API key, see below.)

* brave: Brave search engine - https://search.brave.com/

* bufferoverun: (Requires an API key, see below.) https://tls.bufferover.run

* censys: [Censys search engine](https://search.censys.io/) will use certificates searches to enumerate subdomains and gather emails<br>
  (Requires an API key, see below.) https://censys.io

* certspotter: Cert Spotter monitors Certificate Transparency logs - https://sslmate.com/certspotter/

* criminalip: Specialized Cyber Threat Intelligence (CTI) search engine (Requires an API key, see below.) - https://www.criminalip.io

* crtsh: Comodo Certificate search - https://crt.sh

* duckduckgo: DuckDuckGo search engine - https://duckduckgo.com

* fullhunt: Next-generation attack surface security platform (Requires an API key, see below.) - https://fullhunt.io

* github-code: GitHub code search engine (Requires a GitHub Personal Access Token, see below.) - www.github.com

* hackertarget: Online vulnerability scanners and network intelligence to help organizations - https://hackertarget.com

* hunter: Hunter search engine (Requires an API key, see below.) - https://hunter.io

* hunterhow: Internet search engines for security researchers (Requires an API key, see below.) - https://hunter.how

* intelx: Intelx search engine (Requires an API key, see below.) - http://intelx.io

* netlas: A Shodan or Censys competitor (Requires an API key, see below.) - https://app.netlas.io

* onyphe: Cyber defense search engine (Requires an API key, see below.) - https://www.onyphe.io/

* otx: AlienVault open threat exchange - https://otx.alienvault.com

* pentestTools: Cloud-based toolkit for offensive security testing, focused on web applications and network penetration<br>
  testing (Requires an API key, see below.) - https://pentest-tools.com/

* projecDiscovery: We actively collect and maintain internet-wide assets data, to enhance research and analyse changes around<br>
  DNS for better insights (Requires an API key, see below.) - https://chaos.projectdiscovery.io

* rapiddns: DNS query tool which make querying subdomains or sites of a same IP easy! https://rapiddns.io

* rocketreach: Access real-time verified personal/professional emails, phone numbers, and social media links (Requires an API key,<br>
  see below.) - https://rocketreach.co

* securityTrails: Security Trails search engine, the world's largest repository of historical DNS data (Requires an API key, see<br>
  below.) - https://securitytrails.com

* -s, --shodan: Shodan search engine will search for ports and banners from discovered hosts (Requires an API key, see below.)<br>
  https://shodan.io

* sitedossier: Find available information on a site - http://www.sitedossier.com

* subdomaincenter: A subdomain finder tool used to find subdomains of a given domain - https://www.subdomain.center/

* subdomainfinderc99: A subdomain finder is a tool used to find the subdomains of a given domain - https://subdomainfinder.c99.nl

* threatminer: Data mining for threat intelligence - https://www.threatminer.org/

* tomba: Tomba search engine (Requires an API key, see below.) - https://tomba.io

* urlscan: A sandbox for the web that is a URL and website scanner - https://urlscan.io

* vhost: Bing virtual hosts search

* venacus: Venacus search engine (Requires an API key, see below.) - https://venacus.com

* virustotal: Domain search (Requires an API key, see below.) - https://www.virustotal.com

* whoisxml: Subdomain search (Requires an API key, see below.) - https://subdomains.whoisxmlapi.com/api/pricing

* yahoo: Yahoo search engine

* zoomeye: China's version of Shodan (Requires an API key, see below.) - https://www.zoomeye.org

Active modules:
---------------
* DNS brute force: dictionary brute force enumeration
* Screenshots: Take screenshots of subdomains that were found

Modules that require an API key:
--------------------------------
Documentation to setup API keys can be found at - https://github.com/laramies/theHarvester/wiki/Installation#api-keys

* bevigil - Free upto 50 queries. Pricing can be found here: https://bevigil.com/pricing/osint
* bing
* bufferoverun - uses the free binaAPI
* censys - API keys are required and can be retrieved from your [Censys account](https://search.censys.io/account/api).
* criminalip
* fullhunt
* github
* hunter - limited to 10 on the free plan, so you will need to do -l 10 switch
* hunterhow
* intelx
* netlas - $
* onyphe -$
* pentestTools - $
* projecDiscovery - invite only for now
* rocketreach - $
* securityTrails
* shodan - $
* tomba - Free up to 50 search.
* venacus - $
* whoisxml
* zoomeye

Install and dependencies:
-------------------------
* Python 3.11+
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
