![theHarvester](https://github.com/laramies/theHarvester/blob/master/theHarvester-logo.webp)

![TheHarvester CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Python%20CI/badge.svg) ![TheHarvester Docker Image CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Docker%20Image%20CI/badge.svg)
[![Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/img/badges/Rawsec-inventoried-FF5050_flat_without_logo.svg)](https://inventory.raw.pm/)

About
-----
theHarvester is a simple to use, yet powerful tool designed to be used during the reconnaissance stage of a red
team assessment or penetration test. It performs open source intelligence (OSINT) gathering to help determine
a domain's external threat landscape. The tool gathers names, emails, IPs, subdomains, and URLs by using
multiple public resources that include:

Install and dependencies
------------------------
* Python 3.12 or higher.
* https://github.com/laramies/theHarvester/wiki/Installation

Install uv:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

Clone the repository:
   ```bash
   git clone https://github.com/laramies/theHarvester
   cd theHarvester
   ```

Install dependencies and create a virtual environment:
   ```bash
   uv sync
   ```

Run theHarvester:
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

Passive modules
---------------

* baidu: Baidu search engine (https://www.baidu.com)

* bevigil: CloudSEK BeVigil scans mobile application for OSINT assets (https://bevigil.com/osint-api)

* brave: Brave search engine - now uses official Brave Search API (https://api-dashboard.search.brave.com)

* bufferoverun: Fast domain name lookups for TLS certificates in IPv4 space (https://tls.bufferover.run)

* builtwith: Find out what websites are built with (https://builtwith.com)

* censys: Uses certificates searches to enumerate subdomains and gather emails (https://censys.io)

* certspotter: Cert Spotter monitors Certificate Transparency logs (https://sslmate.com/certspotter)

* criminalip: Specialized Cyber Threat Intelligence (CTI) search engine (https://www.criminalip.io)

* crtsh: Comodo Certificate search (https://crt.sh)

* dehashed: Take your data security to the next level is (https://dehashed.com)

* dnsdumpster: Domain research tool that can discover hosts related to a domain (https://dnsdumpster.com)

* duckduckgo: DuckDuckGo search engine (https://duckduckgo.com)

* fullhunt: Next-generation attack surface security platform (https://fullhunt.io)

* github-code: GitHub code search engine (https://www.github.com)

* hackertarget: Online vulnerability scanners and network intelligence to help organizations (https://hackertarget.com)

* haveibeenpwned: Check if your email address is in a data breach (https://haveibeenpwned.com)

* hunter: Hunter search engine (https://hunter.io)

* hunterhow: Internet search engines for security researchers (https://hunter.how)

* intelx: Intelx search engine (https://intelx.io)

* leaklookup: Data breach search engine (https://leak-lookup.com)

* netlas: A Shodan or Censys competitor (https://app.netlas.io)

* onyphe: Cyber defense search engine (https://www.onyphe.io)

* otx: AlienVault open threat exchange (https://otx.alienvault.com)

* pentesttools: Cloud-based toolkit for offensive security testing, focused on web applications and network penetration testing (https://pentest-tools.com)

* projecdiscovery: Actively collects and maintains internet-wide assets data, to enhance research and analyse changes around DNS for better insights (https://chaos.projectdiscovery.io)

* rapiddns: DNS query tool which make querying subdomains or sites of a same IP easy (https://rapiddns.io)

* rocketreach: Access real-time verified personal/professional emails, phone numbers, and social media links (https://rocketreach.co)

* securityscorecard: helps TPRM and SOC teams detect, prioritize, and remediate vendor risk across their entire supplier ecosystem at scale (https://securityscorecard.com)

* securityTrails: Security Trails search engine, the world's largest repository of historical DNS data (https://securitytrails.com)

* -s, --shodan: Shodan search engine will search for ports and banners from discovered hosts (https://shodan.io)

* subdomaincenter: A subdomain finder tool used to find subdomains of a given domain (https://www.subdomain.center)

* subdomainfinderc99: A subdomain finder is a tool used to find the subdomains of a given domain (https://subdomainfinder.c99.nl)

* threatminer: Data mining for threat intelligence (https://www.threatminer.org)

* tomba: Tomba search engine (https://tomba.io)

* urlscan: A sandbox for the web that is a URL and website scanner (https://urlscan.io)

* venacus: Venacus search engine (https://venacus.com)

* virustotal: Domain search (https://www.virustotal.com)

* whoisxml: Subdomain search (https://subdomains.whoisxmlapi.com/api/pricing)

* yahoo: Yahoo search engine (https://www.yahoo.com)

* zoomeye: China's version of Shodan (https://www.zoomeye.org)

Active modules
--------------
* DNS brute force: dictionary brute force enumeration
* Screenshots: Take screenshots of subdomains that were found

Modules that require an API key
-------------------------------
Documentation to setup API keys can be found at - https://github.com/laramies/theHarvester/wiki/Installation#api-keys

* bevigil - 50 free queries/month, 1k queries/month $50
* brave - Free plan available, Pro plans for higher limits
* bufferoverun - 100 free queries/month, 10k/month $25
* builtwith - 50 free queries ever, $2950/yr
* censys - 500 credits $100
* criminalip - 100 free queries/month, 700k/month $59
* dehashed - 500 credts $15, 5k credits $150
* dnsdumpster - 50 free querries/day, $49
* fullhunt - 50 free queries, 200 queries $29/month, 500 queries $59/month 
* github-code
* haveibeenpwned - 10 email searches/min $4.50, 50 email searches/min $22
* hunter - 50 credits/month free, 12k credits/yr $34
* hunterhow - 10k free API results per 30 days, 50k API results per 30 days $10
* intelx
* leaklookup - 20 credits $10, 50 credits $20, 140 credits $50, 300 credits $100
* netlas - 50 free requests/day, 1k requests $49, 10k requests $249
* onyphe - 10M results/month $587
* pentesttools - 5 assets netsec $95/month, 5 assets webnetsec $140/month
* projecdiscovery - requires work email. Free monthly discovery and vulnerability scans on sign-up email domain, enterprise $
* rocketreach - 100 email lookups/month $48, 250 email lookups/month $108
* securityscorecard
* securityTrails - 50 free queries/month, 20k queries/month $500
* shodan - Freelancer $69 month, Small Business $359 month
* tomba - 25 searches/month free, 1k searches/month $39, 5k searches/month $89
* venacus - 1 search/day free, 10 searches/day $12, 30 searches/day $36
* whoisxml - 2k queries $50, 5k queries $105
* zoomeye - 5 results/day free, 30/results/day $190/yr

## Package versions
[![Packaging status](https://repology.org/badge/vertical-allrepos/theharvester.svg)](https://repology.org/project/theharvester/versions)

Comments, bugs, and requests
----------------------------
* [![Twitter Follow](https://img.shields.io/twitter/follow/laramies.svg?style=social&label=Follow)](https://twitter.com/laramies) Christian Martorella @laramies
  cmartorella@edge-security.com
* [![Twitter Follow](https://img.shields.io/twitter/follow/NotoriousRebel1.svg?style=social&label=Follow)](https://twitter.com/NotoriousRebel1) Matthew Brown @NotoriousRebel1
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1

Main contributors
-----------------
* [![Twitter Follow](https://img.shields.io/twitter/follow/NotoriousRebel1.svg?style=social&label=Follow)](https://twitter.com/NotoriousRebel1) Matthew Brown @NotoriousRebel1
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1
* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts


Thanks
------
* John Matherly - Shodan project
* Ahmed Aboul Ela - subdomain names dictionaries (big and small)
