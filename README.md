![theHarvester](https://github.com/laramies/theHarvester/blob/master/theHarvester-logo.webp)

![TheHarvester CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Python%20CI/badge.svg) ![TheHarvester Docker Image CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Docker%20Image%20CI/badge.svg)
[![Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/img/badges/Rawsec-inventoried-FF5050_flat_without_logo.svg)](https://inventory.raw.pm/)

What is this?
-------------
theHarvester is a simple to use, yet powerful tool designed to be used during the reconnaissance stage of a red
team assessment or penetration test. It performs open source intelligence (OSINT) gathering to help determine
a domain's external threat landscape. The tool gathers names, emails, IPs, subdomains, and URLs by using
multiple public resources that include:

Install and dependencies:
-------------------------
* Python 3.12 or higher.
* https://github.com/laramies/theHarvester/wiki/Installation


## Requirements
Recommend using uv.

1. Install uv:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/laramies/theHarvester
   cd theHarvester
   ```

3. Install dependencies and create a virtual environment:
   ```bash
   uv sync
   ```

4. Run theHarvester:
   ```bash
   uv run theHarvester
   ```

## Development

To install development dependencies:
```bash
uv sync --extra dev
```

To run tests:
```bash
uv run pytest
```

To run linting and formatting:
```bash
uv run ruff check
```
```bash
uv run ruff format
```

Passive modules:
----------------

* baidu: Baidu search engine - www.baidu.com

* bevigil: CloudSEK BeVigil scans mobile application for OSINT assets (Requires an API key, see below.) - https://bevigil.com/osint-api

* bing: Microsoft search engine - https://www.bing.com

* bingapi: Microsoft search engine, through the API (Requires an API key, see below.)

* brave: Brave search engine - https://search.brave.com/

* bufferoverun: Fast domain name lookups for TLS certificates in IPv4 space (Requires an API key, see below.) https://tls.bufferover.run

* builtwith: Find out what websites are built with (Requires an API key, see below.) - https://builtwith.com

* censys: [Censys search engine](https://search.censys.io/) will use certificates searches to enumerate subdomains and gather emails<br>
  (Requires an API key, see below.) https://censys.io

* certspotter: Cert Spotter monitors Certificate Transparency logs - https://sslmate.com/certspotter/

* criminalip: Specialized Cyber Threat Intelligence (CTI) search engine (Requires an API key, see below.) - https://www.criminalip.io

* crtsh: Comodo Certificate search - https://crt.sh

* dehashed: Take your data security to the next level (Requires an API key, see below.) - https://dehashed.com

* dnsdumpster: Domain research tool that can discover hosts related to a domain - https://dnsdumpster.com

* duckduckgo: DuckDuckGo search engine - https://duckduckgo.com

* fullhunt: Next-generation attack surface security platform (Requires an API key, see below.) - https://fullhunt.io

* github-code: GitHub code search engine (Requires a GitHub Personal Access Token, see below.) - www.github.com

* hackertarget: Online vulnerability scanners and network intelligence to help organizations - https://hackertarget.com

* haveibeenpwned: Check if your email address is in a data breach (Requires an API key, see below.) - https://haveibeenpwned.com

* hunter: Hunter search engine (Requires an API key, see below.) - https://hunter.io

* hunterhow: Internet search engines for security researchers (Requires an API key, see below.) - https://hunter.how

* intelx: Intelx search engine (Requires an API key, see below.) - http://intelx.io

* leaklookup: Data breach search engine (Requires an API key, see below.) - https://leak-lookup.com

* netlas: A Shodan or Censys competitor (Requires an API key, see below.) - https://app.netlas.io

* onyphe: Cyber defense search engine (Requires an API key, see below.) - https://www.onyphe.io/

* otx: AlienVault open threat exchange - https://otx.alienvault.com

* pentestTools: Cloud-based toolkit for offensive security testing, focused on web applications and network penetration testing<br>
(Requires an API key, see below.) - https://pentest-tools.com/

* projecDiscovery: We actively collect and maintain internet-wide assets data, to enhance research and analyse changes around DNS<br>
for better insights (Requires an API key, see below.) - https://chaos.projectdiscovery.io

* rapiddns: DNS query tool which make querying subdomains or sites of a same IP easy! https://rapiddns.io

* rocketreach: Access real-time verified personal/professional emails, phone numbers, and social media links (Requires an API key, see below.) - https://rocketreach.co

* securityscorecard: helps TPRM and SOC teams detect, prioritize, and remediate vendor risk across their entire supplier ecosystem at scale (Requires an API key, see below.) - https://securityscorecard.com

* securityTrails: Security Trails search engine, the world's largest repository of historical DNS data (Requires an API key, see below.) - https://securitytrails.com

* -s, --shodan: Shodan search engine will search for ports and banners from discovered hosts (Requires an API key, see below.) - https://shodan.io

* sitedossier: Find available information on a site - http://www.sitedossier.com

* subdomaincenter: A subdomain finder tool used to find subdomains of a given domain - https://www.subdomain.center/

* subdomainfinderc99: A subdomain finder is a tool used to find the subdomains of a given domain - https://subdomainfinder.c99.nl

* threatminer: Data mining for threat intelligence - https://www.threatminer.org/

* tomba: Tomba search engine (Requires an API key, see below.) - https://tomba.io

* urlscan: A sandbox for the web that is a URL and website scanner - https://urlscan.io

* venacus: Venacus search engine (Requires an API key, see below.) - https://venacus.com

* vhost: Bing virtual hosts search

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
* builtwith
* censys - API keys are required and can be retrieved from your [Censys account](https://search.censys.io/account/api).
* criminalip
* dehashed
* fullhunt
* github-code
* haveibeenpwned
* hunter - limited to 10 on the free plan, so you will need to do -l 10 switch
* hunterhow
* intelx
* leaklookup
* netlas - $
* onyphe -$
* pentestTools - $
* projecDiscovery - invite only for now
* rocketreach - $
* securityscorecard
* securityTrails
* shodan - $
* tomba - Free up to 50 search.
* venacus - $
* whoisxml
* zoomeye

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
