```
*******************************************************************
*                                                                 *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 3.0.6 v65                                          *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
* cmartorella@edge-security.com                                   *
*******************************************************************
```

What is this?
-------------
theHarvester is a very simple, yet effective tool designed to be used in the early stages<br>
of a penetration test. Use it for open source intelligence gathering and helping to determine<br>
a company's external threat landscape on the internet. It gathers names, emails, subdomains,<br>
and virtual hosts using multiple public data sources that include:

Passive:
--------
* baidu: Baidu search engine

* bing: Microsoft search engine - www.bing.com

* bingapi: Microsoft search engine, through the API (Requires API key, see below.)

* censys:

* crtsh: Comodo Certificate search - www.crt.sh

* cymon:

* dogpile: Dogpile search engine - www.dogpile.com

* google: Google search engine (Optional Google dorking.) - www.google.com

* googleCSE: Google custom search engine

* googleplus: Users that work in target company (Uses Google search.)

* google-certificates: Google Certificate Transparency report

* google-profiles: Google search engine, specific search for Google profiles

* hunter: Hunter search engine (Requires API key, see below.) - www.hunter.io

* linkedin: Google search engine, specific search for Linkedin users

* netcraft:

* pgp: PGP key server - mit.edu

* securitytrails: Security Trails search engine, the world's largest repository<br>
  of historical DNS data (Requires API key, see below.) - www.securitytrails.com

* shodan: Shodan search engine, will search for ports and banners from discovered<br>
  hosts - www.shodanhq.com

* threatcrowd: Open source threat intelligence - www.threatcrowd.org

* trello: Search trello boards (Uses Google search.)

* twitter: Twitter accounts related to a specific domain (Uses Google search.)

* vhost: Bing virtual hosts search

* virustotal:

* yahoo: Yahoo search engine

* all:

Active:
-------
* DNS brute force: dictionary brute force enumeration
* DNS reverse lookup: reverse lookup of IP´s discovered in order to find hostnames
* DNS TDL expansion: TLD dictionary brute force enumeration

Modules that require an API key:
--------------------------------
Add your keys to discovery/constants.py

* googleCSE: API key and CSE ID
* hunter: API key
* securitytrails: API key
* shodan: API key

Dependencies:
-------------
* Do ```pip3 install -r requirements```

Changelog in 3.0:
-----------------
* Subdomain takeover checks.
* Port scanning (basic).
* Improved DNS dictionary.
* Shodan DB search fixed.
* Result storage in Sqlite.

Comments, bugs, or requests?
----------------------------
cmartorella@edge-security.com

Thanks:
-------
* Matthew Brown @NotoriousRebel
* Janos Zold @Jzold
* John Matherly - Shodan project
* Lee Baird @discoverscripts - suggestions and bugs reporting
* Ahmed Aboul Ela - subdomain names dictionaries (big and small)
