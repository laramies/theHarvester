![theHarvester](https://github.com/laramies/theHarvester/blob/master/theHarvester-logo.png)

[![Build Status](https://travis-ci.com/laramies/theHarvester.svg?branch=master)](https://travis-ci.com/laramies/theHarvester) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/laramies/theHarvester.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/laramies/theHarvester/context:python)
[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat_without_logo.svg)](https://inventory.rawsec.ml/)

What is this?
-------------
theHarvester is a very simple to use, yet powerful and effective tool designed to be used in the early statges of a<br>
penetration test or red team engagement. Use it for open source intelligence (OSINT) gathering to help determine a<br>
company's external threat landscape on the internet. The tool gathers emails, names, subdomains, IPs and URLs using<br>
multiple public data sources that include:

Passive:
--------
* baidu: Baidu search engine - www.baidu.com

* bing: Microsoft search engine - www.bing.com

* bingapi: Microsoft search engine, through the API (Requires an API key, see below.)

* Bufferoverun: Uses data from Rapid7's Project Sonar - www.rapid7.com/research/project-sonar/

* CertSpotter: Cert Spotter monitors Certificate Transparency logs - https://sslmate.com/certspotter/

* crtsh: Comodo Certificate search - www.crt.sh

* dnsdumpster: DNSdumpster search engine - dnsdumpster.com

* dogpile: Dogpile search engine - www.dogpile.com

* duckduckgo: DuckDuckGo search engine - www.duckduckgo.com

* Exalead: a Meta search engine - www.exalead.com/search

* github-code: GitHub code search engine (Requires a GitHub Personal Access Token, see below.) - www.github.com

* google: Google search engine (Optional Google dorking.) - www.google.com

* hunter: Hunter search engine (Requires an API key, see below.) - www.hunter.io

* intelx: Intelx search engine (Requires an API key, see below.) - www.intelx.io

* linkedin: Google search engine, specific search for LinkedIn users - www.linkedin.com

* netcraft: Internet Security and Data Mining - www.netcraft.com

* otx: AlienVault Open Threat Exchange - otx.alienvault.com

* securityTrails: Security Trails search engine, the world's largest repository of historical DNS data<br>
  (Requires an API key, see below.) - www.securitytrails.com

* shodan: Shodan search engine, will search for ports and banners from discovered hosts - www.shodanhq.com

* Spyse: Web research tools for professionals (Requires an API key.) - spyse.com

* Suip: Web research tools that can take over 10 minutes to run, but worth the wait - suip.biz

* threatcrowd: Open source threat intelligence - www.threatcrowd.org

* trello: Search trello boards (Uses Google search.)

* twitter: Twitter accounts related to a specific domain (Uses Google search.)

* vhost: Bing virtual hosts search

* virustotal: virustotal.com domain search

* yahoo: Yahoo search engine


Active:
-------
* DNS brute force: dictionary brute force enumeration


Modules that require an API key:
--------------------------------
Add your keys to api-keys.yaml

* bing
* github
* hunter
* intelx
* securityTrails
* shodan
* spyse


Install and dependencies:
-------------------------
* Python 3.7+
* python3 -m pip install pipenv
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
