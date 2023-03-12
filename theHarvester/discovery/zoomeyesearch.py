from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from theHarvester.parsers import myparser
from typing import List
import asyncio
import re


class SearchZoomEye:

    def __init__(self, word, limit) -> None:
        self.word = word
        self.limit = limit
        self.key = Core.zoomeye_key()
        # NOTE for ZoomEye you get a system recharge on the 1st of every month
        # Which resets your balance to 10000 requests
        # If you wish to extract as many subdomains as possible visit the fetch_subdomains
        # To see how
        if self.key is None:
            raise MissingKey('zoomeye')
        self.baseurl = 'https://api.zoomeye.org/host/search'
        self.proxy = False
        self.totalasns: List = list()
        self.totalhosts: List = list()
        self.interestingurls: List = list()
        self.totalips: List = list()
        self.totalemails: List = list()
        # Regex used is directly from: https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py#L29
        # Maybe one day it will be a pip package
        # Regardless LinkFinder is an amazing tool!
        self.iurl_regex = r"""
          (?:"|')                               # Start newline delimiter
          (
            ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
            [^"'/]{1,}\.                        # Match a domainname (any character + dot)
            [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
            |
            ((?:/|\.\./|\./)                    # Start with /,../,./
            [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
            [^"'><,;|()]{1,})                   # Rest of the characters can't be
            |
            ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
            [a-zA-Z0-9_\-/]{1,}                 # Resource name
            \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
            [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-]{1,}                 # filename
            \.(?:php|asp|aspx|jsp|json|
                 action|html|js|txt|xml)        # . + extension
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
          )
          (?:"|')                               # End newline delimiter
        """
        self.iurl_regex = re.compile(self.iurl_regex, re.VERBOSE)

    async def fetch_subdomains(self) -> None:
        # Based on docs from: https://www.zoomeye.org/doc#search-sub-domain-ip
        headers = {
            'API-KEY': self.key,
            'User-Agent': Core.get_user_agent()
        }

        subdomain_search_endpoint = f'https://api.zoomeye.org/domain/search?q={self.word}&type=0&'

        response = await AsyncFetcher.fetch_all([subdomain_search_endpoint + 'page=1'],
                                                json=True, proxy=self.proxy, headers=headers)
        # Make initial request to determine total number of subdomains
        resp = response[0]
        if resp['status'] != 200:
            return
        total = resp['total']
        # max number of results per request seems to be 30
        # NOTE: If you wish to get as many subdomains as possible
        # Change the line below to:
        # self.limit = (total // 30) + 1
        self.limit = self.limit if total > self.limit else (total // 30) + 1
        self.totalhosts.extend([item["name"] for item in resp["list"]])
        for i in range(2, self.limit):
            response = await AsyncFetcher.fetch_all([subdomain_search_endpoint + f'page={i}'],
                                                    json=True, proxy=self.proxy, headers=headers)
            resp = response[0]
            if resp['status'] != 200:
                return
            found_subdomains = [item["name"] for item in resp["list"]]
            if len(found_subdomains) == 0:
                break
            self.totalhosts.extend(found_subdomains)
            if i % 10 == 0:
                await asyncio.sleep(get_delay() + 1)

    async def do_search(self) -> None:
        headers = {
            'API-KEY': self.key,
            'User-Agent': Core.get_user_agent()
        }
        # Fetch subdomains first
        await self.fetch_subdomains()
        params = (
            ('query', f'site:{self.word}'),
            ('page', '1'),
        )
        response = await AsyncFetcher.fetch_all([self.baseurl], json=True, proxy=self.proxy, headers=headers,
                                                params=params)
        # The First request determines how many pages there in total
        resp = response[0]
        total_pages = int(resp['available'])
        self.limit = self.limit if total_pages > self.limit else total_pages
        self.limit = 3 if self.limit == 2 else self.limit
        cur_page = 2 if self.limit >= 2 else -1
        # Means there is only one-page
        # hostnames, emails, ips, asns, iurls
        nomatches_counter = 0
        # cur_page = -1
        if cur_page == -1:
            # No need to do loop just parse and leave
            if 'matches' in resp.keys():
                hostnames, emails, ips, asns, iurls = await self.parse_matches(resp['matches'])
                self.totalhosts.extend(hostnames)
                self.totalemails.extend(emails)
                self.totalips.extend(ips)
                self.totalasns.extend(asns)
                self.interestingurls.extend(iurls)
        else:
            if 'matches' in resp.keys():
                # Parse out initial results and then continue to loop
                hostnames, emails, ips, asns, iurls = await self.parse_matches(resp['matches'])
                self.totalhosts.extend(hostnames)
                self.totalemails.extend(emails)
                self.totalips.extend(ips)
                self.totalasns.extend(asns)
                self.interestingurls.extend(iurls)

            for num in range(2, self.limit):
                # print(f'Currently on page: {num}')
                params = (
                    ('query', f'site:{self.word}'),
                    ('page', f'{num}'),
                )
                response = await AsyncFetcher.fetch_all([self.baseurl], json=True, proxy=self.proxy, headers=headers,
                                                        params=params)
                resp = response[0]
                if 'matches' not in resp.keys():
                    print(f'Your resp: {resp}')
                    print('Match not found in keys')
                    break

                hostnames, emails, ips, asns, iurls = await self.parse_matches(resp['matches'])

                if len(hostnames) == 0 and len(emails) == 0 and len(ips) == 0 \
                        and len(asns) == 0 and len(iurls) == 0:
                    nomatches_counter += 1

                if nomatches_counter >= 5:
                    break

                self.totalhosts.extend(hostnames)
                self.totalemails.extend(emails)
                self.totalips.extend(ips)
                self.totalasns.extend(asns)
                self.interestingurls.extend(iurls)

                if num % 10 == 0:
                    await asyncio.sleep(get_delay() + 1)

    async def parse_matches(self, matches):
        # Helper function to parse items from match json
        # ips = {match["ip"] for match in matches}
        ips = set()
        iurls = set()
        hostnames = set()
        asns = set()
        emails = set()
        for match in matches:
            try:
                ips.add(match['ip'])

                if 'geoinfo' in match.keys():
                    asns.add(f"AS{match['geoinfo']['asn']}")

                if 'rdns_new' in match.keys():
                    rdns_new = match['rdns_new']

                    if ',' in rdns_new:
                        parts = str(rdns_new).split(',')
                        rdns_new = parts[0]
                        if len(parts) == 2:
                            hostnames.add(parts[1])
                        rdns_new = rdns_new[:-1] if rdns_new[-1] == '.' else rdns_new
                        hostnames.add(rdns_new)
                    else:
                        rdns_new = rdns_new[:-1] if rdns_new[-1] == '.' else rdns_new
                        hostnames.add(rdns_new)

                if 'rdns' in match.keys():
                    rdns = match['rdns']
                    rdns = rdns[:-1] if rdns[-1] == '.' else rdns
                    hostnames.add(rdns)

                if 'portinfo' in match.keys():
                    # re.
                    temp_emails = set(await self.parse_emails(match['portinfo']['banner']))
                    emails.update(temp_emails)
                    hostnames.update(set(await self.parse_hostnames(match['portinfo']['banner'])))
                    iurls = {str(iurl.group(1)).replace('"', '') for iurl
                             in re.finditer(self.iurl_regex, match['portinfo']['banner'])
                             if self.word in str(iurl.group(1))}
            except Exception as e:
                print(f'An exception has occurred: {e}')
        return hostnames, emails, ips, asns, iurls

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()  # Only need to do it once.

    async def parse_emails(self, content):
        rawres = myparser.Parser(content, self.word)
        return await rawres.emails()

    async def parse_hostnames(self, content):
        rawres = myparser.Parser(content, self.word)
        return await rawres.hostnames()

    async def get_hostnames(self):
        return set(self.totalhosts)

    async def get_emails(self):
        return set(self.totalemails)

    async def get_ips(self):
        return set(self.totalips)

    async def get_asns(self):
        return set(self.totalasns)

    async def get_interestingurls(self):
        return set(self.interestingurls)
