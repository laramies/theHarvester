![theHarvester](https://github.com/laramies/theHarvester/blob/master/theHarvester-logo.png)

![TheHarvester CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Python%20CI/badge.svg) ![TheHarvester Docker Image CI](https://github.com/laramies/theHarvester/workflows/TheHarvester%20Docker%20Image%20CI/badge.svg) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/laramies/theHarvester.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/laramies/theHarvester/context:python)
[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat_without_logo.svg)](https://inventory.rawsec.ml/)

What is this?
-------------
theHarvester is a very simple to use, yet powerful and effective tool designed to be used in the early stages of a<br>
penetration test or red team engagement. Use it for open source intelligence (OSINT) gathering to help determine a<br>
company's external threat landscape on the internet. The tool gathers emails, names, subdomains, IPs and URLs using<br>
multiple public data sources that include:

Passive:
--------
* baidu: Baidu search engine - www.baidu.com

* bing: Microsoft search engine - www.bing.com

* bingapi: Microsoft search engine, through the API (Requires an API key, see below.)

* bufferoverun: Uses data from Rapid7's Project Sonar - www.rapid7.com/research/project-sonar/

* certspotter: Cert Spotter monitors Certificate Transparency logs - https://sslmate.com/certspotter/

* crtsh: Comodo Certificate search - https://crt.sh

* dnsdumpster: DNSdumpster search engine - https://dnsdumpster.com

* duckduckgo: DuckDuckGo search engine - www.duckduckgo.com

* exalead: a Meta search engine - www.exalead.com/search

* github-code: GitHub code search engine (Requires a GitHub Personal Access Token, see below.) - www.github.com

* google: Google search engine (Optional Google dorking.) - www.google.com

* hackertarget: Online vulnerability scanners and network intelligence to help organizations - https://hackertarget.com

* hunter: Hunter search engine (Requires an API key, see below.) - www.hunter.io

* intelx: Intelx search engine (Requires an API key, see below.) - www.intelx.io

* linkedin: Google search engine, specific search for LinkedIn users - www.linkedin.com

* linkedin_links: 

* netcraft: Internet Security and Data Mining - www.netcraft.com

* otx: AlienVault Open Threat Exchange - https://otx.alienvault.com

* pentesttools: Powerful Penetration Testing Tools, Easy to Use (Needs an API key and is not free for API access) - https://pentest-tools.com/home

* projecdiscovery: We actively collect and maintain internet-wide assets data, 
to enhance research and analyse changes around DNS for better insights - https://chaos.projectdiscovery.io
(Requires an API key)

* qwant: Qwant search engine - www.qwant.com

* rapiddns: DNS query tool which make querying subdomains or sites of a same IP easy! https://rapiddns.io

* securityTrails: Security Trails search engine, the world's largest repository of historical DNS data<br>
  (Requires an API key, see below.) - www.securitytrails.com

* shodan: Shodan search engine, will search for ports and banners from discovered hosts - www.shodanhq.com

* spyse: Web research tools for professionals (Requires an API key.) - https://spyse.com

* sublist3r: Fast subdomains enumeration tool for penetration testers - https://api.sublist3r.com/search.php?domain=example.com

* threatcrowd: Open source threat intelligence - www.threatcrowd.org

* threatminer: Data mining for threat intelligence - https://www.threatminer.org/

* trello: Search trello boards (Uses Google search.)

* twitter: Twitter accounts related to a specific domain (Uses Google search.)

* urlscan: A sandbox for the web that is a URL and website scanner - https://urlscan.io

* vhost: Bing virtual hosts search

* virustotal: virustotal.com domain search

* yahoo: Yahoo search engine


Active:
-------
* DNS brute force: dictionary brute force enumeration
* Screenshots: Take screenshots of subdomains that were found

Modules that require an API key:
--------------------------------
Documentation to setup API keys can be found at - https://github.com/laramies/theHarvester/wiki/Installation#api-keys

* bing
* github
* hunter - limited to 10 on the free plan so you will ned to do -l 10 switch
* intelx
* pentesttools
* projecdiscovery - invite only for now
* securityTrails
* shodan
* spyse - need to have a paid account be able to use the api now


Install and dependencies:
-------------------------
* Python 3.7+
* https://github.com/laramies/theHarvester/wiki/Installation


Comments, bugs and requests:
----------------------------
* [![Twitter Follow](https://img.shields.io/twitter/follow/laramies.svg?style=social&label=Follow)](https://twitter.com/laramies) Christian Martorella @laramies
cmartorella@edge-security.com
* [![Twitter Follow](https://img.shields.io/twitter/follow/NotoriousRebel1.svg?style=social&label=Follow)](https://twitter.com/NotoriousRebel1) Matthew Brown @NotoriousRebel1
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1


Main contributors:
------------------
* [![Twitter Follow](https://img.shields.io/twitter/follow/NotoriousRebel1.svg?style=social&label=Follow)](https://twitter.com/NotoriousRebel1) Matthew Brown @NotoriousRebel1
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1
* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts 
* [![LinkedIn](https://static.licdn.com/scds/common/u/img/webpromo/btn_viewmy_160x25.png)](https://www.linkedin.com/in/janoszold/)  Janos Zold


Thanks:
-------
* John Matherly - Shodan project
* Ahmed Aboul Ela - subdomain names dictionaries (big and small)
