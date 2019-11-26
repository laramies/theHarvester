![theHarvester](https://github.com/laramies/theHarvester/blob/master/theHarvester-logo.png)

[![Build Status](https://travis-ci.com/laramies/theHarvester.svg?branch=master)](https://travis-ci.com/laramies/theHarvester) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/laramies/theHarvester.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/laramies/theHarvester/context:python)
[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat_without_logo.svg)](https://inventory.rawsec.ml/)

What is this?
-------------
theHarvester is a very simple, yet effective tool designed to be used in the early<br>
stages of a penetration test. Use it for open source intelligence gathering and<br>
helping to determine a company's external threat landscape on the internet. The<br>
tool gathers emails, names, subdomains, IPs, and URLs using multiple public data<br>
sources that include:

Passive:
--------
* baidu: Baidu search engine - www.baidu.com

* bing: Microsoft search engine - www.bing.com

* bingapi: Microsoft search engine, through the API (Requires an API key, see below.)

* CertSpotter: Cert Spotter monitors Certificate Transparency logs - https://sslmate.com/certspotter/

* crtsh: Comodo Certificate search - www.crt.sh

* dnsdumpster: DNSdumpster search engine - dnsdumpster.com

* dogpile: Dogpile search engine - www.dogpile.com

* duckduckgo: DuckDuckGo search engine - www.duckduckgo.com

* Exalead: a Meta search engine - https://www.exalead.com/search

* github-code: Github code search engine (Requires a Github Personal Access Token, see below.) - www.github.com

* google: Google search engine (Optional Google dorking.) - www.google.com

* hunter: Hunter search engine (Requires an API key, see below.) - www.hunter.io

* intelx: Intelx search engine (Requires an API key, see below.) - www.intelx.io

* linkedin: Google search engine, specific search for LinkedIn users - www.linkedin.com

* netcraft: Internet Security and Data Mining - www.netcraft.com

* otx: AlienVault Open Threat Exchange - https://otx.alienvault.com

* securityTrails: Security Trails search engine, the world's largest repository<br>
  of historical DNS data (Requires an API key, see below.) - www.securitytrails.com

* shodan: Shodan search engine, will search for ports and banners from discovered<br>
  hosts - www.shodanhq.com

* Spyse: Web research tools for professionals (Requires an API key.) - https://spyse.com/

* Suip: Web research tools that can take over 10 minutes to run, but worth the wait. - https://suip.biz/

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

Dependencies:
-------------
* Python 3.7+
* python3 -m pip install pipenv
* pipenv install

Comments, bugs, or requests?
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
