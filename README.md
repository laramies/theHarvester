```
*******************************************************************
*                                                                 *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 3.0.6 v364                                         *
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
* baidu: Baidu search engine

* bing: Microsoft search engine - www.bing.com

* bingapi: Microsoft search engine, through the API (Requires API key, see below.)

* censys: Censys.io search engine

* crtsh: Comodo Certificate search - www.crt.sh

* cymon: Cymon.io search engine

* dogpile: Dogpile search engine - www.dogpile.com

* duckduckgo: DuckDuckGo search engine - www.duckduckgo.com 

* google: Google search engine (Optional Google dorking.) - www.google.com

* google-certificates: Google Certificate Transparency report

* hunter: Hunter search engine (Requires API key, see below.) - www.hunter.io

* intelx: Intelx search engine (Requires API key, see below.) - www.intelx.io

* linkedin: Google search engine, specific search for Linkedin users

* netcraft: Netcraft Data Mining

* securityTrails: Security Trails search engine, the world's largest repository<br>
  of historical DNS data (Requires API key, see below.) - www.securitytrails.com

* shodan: Shodan search engine, will search for ports and banners from discovered<br>
  hosts - www.shodanhq.com

* threatcrowd: Open source threat intelligence - www.threatcrowd.org

* trello: Search trello boards (Uses Google search.)

* twitter: Twitter accounts related to a specific domain (Uses Google search.)

* vhost: Bing virtual hosts search

* virustotal: Virustotal.com domain search  

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
cmartorella@edge-security.com

Main contributors:
------------------
* Matthew Brown @NotoriousRebel
* Janos Zold @Jzold
* Lee Baird @discoverscripts [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts)
* Jay Townsend @L1ghtn1ng [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1)

Thanks:
-------
* John Matherly - Shodan project
* Ahmed Aboul Ela - subdomain names dictionaries (big and small)
