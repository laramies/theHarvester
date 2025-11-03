import asyncio
import math
import re
from collections.abc import Iterable
from typing import Any

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser


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
        # API v2 base
        self.baseurl = 'https://api.zoomeye.ai/host/search'
        self.domain_url = 'https://api.zoomeye.ai/domain/search'
        self.proxy = False
        self.totalasns: list = list()
        self.totalhosts: list = list()
        self.interestingurls: list = list()
        self.totalips: list = list()
        self.totalemails: list = list()
        # Regex used is directly from: https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py#L29
        # Maybe one day it will be a pip package
        # Regardless LinkFinder is an amazing tool!
        regex_str = r"""
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
        self.iurl_regex = re.compile(regex_str, re.VERBOSE)

    def _build_headers(self) -> dict[str, str]:
        # API v2 uses API-KEY header
        return {'API-KEY': self.key, 'User-Agent': Core.get_user_agent()}

    @staticmethod
    def _is_success(resp: dict[str, Any]) -> bool:
        # Accept multiple success indicators across versions
        try:
            if 'code' in resp:
                # v2 style often uses code==0 for success
                return resp.get('code') in (0, 200)
            if 'status' in resp and isinstance(resp.get('status'), int):
                # some responses put HTTP-like code here
                return resp.get('status') in (0, 200)
        except Exception as e:
            print(f'An error occurred while trying to parse {resp} : {e}')
            return False

        # If no explicit status, assume success and let parsing validate
        return True

    @staticmethod
    def _unwrap_data(resp: dict[str, Any]) -> dict[str, Any]:
        # Many v2 endpoints return {'code':0,'data':{...}}
        data = resp.get('data')
        return data if isinstance(data, dict) else resp

    @staticmethod
    def _page_total_from_payload(payload: dict[str, Any], page_size: int) -> int:
        # Prefer explicit page total if provided
        if 'available' in payload:
            try:
                return int(payload['available'])
            except ValueError:
                print('Payload availablity is not a integer')
            except Exception as e:
                print(f'An error occurred in page_total_from_payload : {e}')
        total_results = payload.get('total') or payload.get('count') or payload.get('total_count')
        if isinstance(total_results, int) and total_results >= 0:
            size = payload.get('size') or page_size
            try:
                size_int = int(size)
                size_int = size_int if size_int > 0 else page_size
            except Exception:
                size_int = page_size
            return max(1, math.ceil(total_results / size_int))
        # Fallback: if a list/matches is present, consider at least one page
        if any(k in payload for k in ('matches', 'list', 'results', 'items')):
            return 1
        return 1

    @staticmethod
    def _safe_add_hostname(container: set, value: str | None) -> None:
        if not value or not isinstance(value, str):
            return
        v = value.strip()
        if not v:
            return
        if v.endswith('.'):
            v = v[:-1]
        container.add(v)

    async def fetch_subdomains(self) -> None:
        headers = self._build_headers()
        # type=0 for subdomain search per docs
        size = 30
        params = (('q', self.word), ('type', '0'), ('page', '1'), ('size', str(size)))
        response = await AsyncFetcher.fetch_all(
            [self.domain_url],
            json=True,
            proxy=self.proxy,
            headers=headers,
            params=params,
        )
        if not response:
            return
        raw = response[0] or {}
        if not self._is_success(raw):
            return
        payload = self._unwrap_data(raw)
        total_pages = self._page_total_from_payload(payload, size)
        # If user requested more pages than available, clamp to available
        self.limit = min(self.limit, total_pages) if total_pages >= 1 else self.limit

        # Parse first page
        first_list = payload.get('list') or payload.get('results') or []
        self.totalhosts.extend(
            [item.get('name') or item.get('domain') or item.get('host') for item in first_list if isinstance(item, dict)]
        )

        # Iterate remaining pages
        for i in range(2, self.limit + 1):
            params = (('q', self.word), ('type', '0'), ('page', str(i)), ('size', str(size)))
            response = await AsyncFetcher.fetch_all(
                [self.domain_url],
                json=True,
                proxy=self.proxy,
                headers=headers,
                params=params,
            )
            if not response:
                break
            raw = response[0] or {}
            if not self._is_success(raw):
                break
            payload = self._unwrap_data(raw)
            page_list = payload.get('list') or payload.get('results') or []
            found_subdomains = [
                item.get('name') or item.get('domain') or item.get('host') for item in page_list if isinstance(item, dict)
            ]
            found_subdomains = [x for x in found_subdomains if x]
            if not found_subdomains:
                break
            self.totalhosts.extend(found_subdomains)
            if i % 10 == 0:
                await asyncio.sleep(get_delay() + 1)

    async def do_search(self) -> None:
        headers = self._build_headers()
        # Fetch subdomains first
        await self.fetch_subdomains()

        size = 20
        params = (('query', f'site:{self.word}'), ('page', '1'), ('size', str(size)))
        response = await AsyncFetcher.fetch_all([self.baseurl], json=True, proxy=self.proxy, headers=headers, params=params)
        if not response:
            return
        raw = response[0] or {}
        payload = self._unwrap_data(raw)
        total_pages = self._page_total_from_payload(payload, size)
        self.limit = min(self.limit, total_pages) if total_pages >= 1 else self.limit
        cur_page = 2 if self.limit >= 2 else -1

        nomatches_counter = 0

        def extract_matches(p: dict[str, Any]) -> Iterable[dict]:
            return p.get('matches') or p.get('list') or p.get('results') or []

        if cur_page == -1:
            if isinstance(payload, dict):
                matches = extract_matches(payload)
                if matches:
                    hostnames, emails, ips, asns, iurls = await self.parse_matches(matches)
                    self.totalhosts.extend(hostnames)
                    self.totalemails.extend(emails)
                    self.totalips.extend(ips)
                    self.totalasns.extend(asns)
                    self.interestingurls.extend(iurls)
            return

        # Parse first page then loop
        if isinstance(payload, dict):
            matches = extract_matches(payload)
            if matches:
                hostnames, emails, ips, asns, iurls = await self.parse_matches(matches)
                self.totalhosts.extend(hostnames)
                self.totalemails.extend(emails)
                self.totalips.extend(ips)
                self.totalasns.extend(asns)
                self.interestingurls.extend(iurls)

        for num in range(2, self.limit + 1):
            params = (('query', f'site:{self.word}'), ('page', str(num)), ('size', str(size)))
            response = await AsyncFetcher.fetch_all(
                [self.baseurl],
                json=True,
                proxy=self.proxy,
                headers=headers,
                params=params,
            )
            if not response:
                break
            raw = response[0] or {}
            payload = self._unwrap_data(raw)
            matches = extract_matches(payload)
            if not matches:
                nomatches_counter += 1
                if nomatches_counter >= 5:
                    break
                continue

            hostnames, emails, ips, asns, iurls = await self.parse_matches(matches)

            if len(hostnames) == 0 and len(emails) == 0 and len(ips) == 0 and len(asns) == 0 and len(iurls) == 0:
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
        ips: set[str] = set()
        iurls: set[str] = set()
        hostnames: set[str] = set()
        asns: set[str] = set()
        emails: set[str] = set()

        for match in matches:
            if not isinstance(match, dict):
                continue
            try:
                # IPs
                ip = match.get('ip') or match.get('ip_str') or match.get('ip_str_v4') or match.get('address')
                if isinstance(ip, str):
                    ips.add(ip)

                # ASNs
                asn_val = None
                if isinstance(match.get('geoinfo'), dict):
                    asn_val = match['geoinfo'].get('asn')
                asn_val = asn_val or match.get('asn')
                if asn_val:
                    try:
                        asns.add(f'AS{int(asn_val)}')
                    except Exception:
                        # if already a string like 'AS12345'
                        asns.add(str(asn_val) if str(asn_val).startswith('AS') else f'AS{asn_val!s}')

                # Reverse DNS and hostnames
                rdns_new = match.get('rdns_new')
                if isinstance(rdns_new, str) and rdns_new:
                    if ',' in rdns_new:
                        parts = str(rdns_new).split(',')
                        primary = parts[0]
                        secondary = parts[1] if len(parts) == 2 else None
                        if primary:
                            self._safe_add_hostname(hostnames, primary)
                        if secondary:
                            self._safe_add_hostname(hostnames, secondary)
                    else:
                        self._safe_add_hostname(hostnames, rdns_new)

                rdns = match.get('rdns')
                if isinstance(rdns, str) and rdns:
                    self._safe_add_hostname(hostnames, rdns)

                # Additional hostname-like fields
                for f in ('hostname', 'host', 'domain', 'site', 'fqdn'):
                    self._safe_add_hostname(hostnames, match.get(f))
                for f in ('hostnames', 'domains', 'names'):
                    vals = match.get(f)
                    if isinstance(vals, list):
                        for v in vals:
                            if isinstance(v, str):
                                self._safe_add_hostname(hostnames, v)

                # Banner/content extraction for emails, hostnames, iurls
                banners = []

                portinfo = match.get('portinfo')
                if isinstance(portinfo, dict):
                    b = portinfo.get('banner')
                    if isinstance(b, str) and b:
                        banners.append(b)

                service = match.get('service')
                if isinstance(service, dict):
                    for key in ('banner', 'data', 'raw'):
                        v = service.get(key)
                        if isinstance(v, str) and v:
                            banners.append(v)
                    http = service.get('http')
                    if isinstance(http, dict):
                        for key in ('title', 'html', 'body', 'server', 'raw'):
                            v = http.get(key)
                            if isinstance(v, str) and v:
                                banners.append(v)

                content_blob = '\n'.join(banners)
                if content_blob:
                    temp_emails = set(await self.parse_emails(content_blob))
                    emails.update(temp_emails)
                    hostnames.update(set(await self.parse_hostnames(content_blob)))
                    found_urls = {
                        str(iurl.group(1)).replace('"', '')
                        for iurl in re.finditer(self.iurl_regex, content_blob)
                        if self.word in str(iurl.group(1))
                    }
                    iurls.update(found_urls)

            except Exception as e:
                # Continue processing other matches instead of failing completely
                print(f'ZoomEye parsing error: {e}')

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
