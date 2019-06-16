```
*******************************************************************
*                                                                 *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 3.1.0 dev                                          *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
* cmartorella@edge-security.com                                   *
*******************************************************************
```
[![Build Status](https://travis-ci.com/laramies/theHarvester.svg?branch=master)](https://travis-ci.com/laramies/theHarvester)

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

* bingapi: Microsoft search engine, through the API (Requires API key, see below.)

* censys: Censys.io search engine - www.censys.io

* crtsh: Comodo Certificate search - www.crt.sh

* dnsdumpster: DNSdumpster search engine - dnsdumpster.com

* dogpile: Dogpile search engine - www.dogpile.com

* duckduckgo: DuckDuckGo search engine - www.duckduckgo.com 

* google: Google search engine (Optional Google dorking.) - www.google.com

* google-certificates: Google Certificate Transparency report 

* hunter: Hunter search engine (Requires API key, see below.) - www.hunter.io

* intelx: Intelx search engine (Requires API key, see below.) - www.intelx.io

* linkedin: Google search engine, specific search for Linkedin users - www.linkedin.com

* netcraft: Netcraft Data Mining - www.netcraft.com

* securityTrails: Security Trails search engine, the world's largest repository<br>
  of historical DNS data (Requires API key, see below.) - www.securitytrails.com

* shodan: Shodan search engine, will search for ports and banners from discovered<br>
  hosts - www.shodanhq.com

* threatcrowd: Open source threat intelligence - www.threatcrowd.org

* trello: Search trello boards (Uses Google search.)

* twitter: Twitter accounts related to a specific domain (Uses Google search.)

* vhost: Bing virtual hosts search

* virustotal: virustotal.com domain search

* yahoo: Yahoo search engine

* all: currently a subset of all the most effective plugins

Active:
-------
* DNS brute force: dictionary brute force enumeration
* DNS reverse lookup: reverse lookup of IP´s discovered in order to find hostnames
* DNS TDL expansion: TLD dictionary brute force enumeration

Modules that require an API key:
--------------------------------
Add your keys to api-keys.yaml

* bingapi
* hunter
* intelx
* securityTrails
* shodan

Dependencies:
-------------
* Python 3.6
* python3 -m pip install -r requirements.txt

Comments, bugs, or requests?
----------------------------
* [![Twitter Follow](https://img.shields.io/twitter/follow/laramies.svg?style=social&label=Follow)](https://twitter.com/laramies) Christian Martorella @laramies
* cmartorella@edge-security.com

Main contributors:
------------------
* [![Twitter Follow](https://img.shields.io/twitter/follow/NotoriousRebel1.svg?style=social&label=Follow)](https://twitter.com/NotoriousRebel1) Matthew Brown @NotoriousRebel1
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1
* [![LinkedIn](https://static.licdn.com/scds/common/u/img/webpromo/btn_viewmy_160x25.png)](https://www.linkedin.com/in/janoszold/)  Janos Zold
* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts 

Thanks:
-------
* John Matherly - Shodan project
* Ahmed Aboul Ela - subdomain names dictionaries (big and small)
