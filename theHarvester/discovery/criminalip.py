import asyncio
from urllib.parse import urlparse

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.core import AsyncFetcher, Core


class SearchCriminalIP:
    def __init__(self, word) -> None:
        self.word = word.lower().strip()
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.asns: set = set()
        self.key = Core.criminalip_key()
        if self.key is None:
            raise MissingKey('criminalip')
        self.proxy = False

    def _normalize_host(self, hostname: str | None) -> str | None:
        if not isinstance(hostname, str):
            return None

        cleaned = hostname.strip().lower().rstrip('.')
        if not cleaned:
            return None

        if cleaned.startswith('*.'):
            cleaned = cleaned[2:]

        if ':' in cleaned and cleaned.count(':') == 1:
            host, port = cleaned.rsplit(':', 1)
            if port.isdigit():
                cleaned = host

        if cleaned == self.word or cleaned.endswith('.' + self.word):
            return cleaned
        return None

    def _add_host(self, hostname: str | None, include_root: bool = True) -> bool:
        normalized = self._normalize_host(hostname)
        if normalized is None:
            return False
        if include_root is False and normalized == self.word:
            return False
        self.totalhosts.add(normalized)
        return True

    def _add_host_from_url(self, url: str | None) -> None:
        if not isinstance(url, str) or not url:
            return
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        if not netloc:
            return
        if '@' in netloc:
            netloc = netloc.rsplit('@', 1)[1]
        self._add_host(netloc)

    def _add_ip(self, ip: str | None) -> None:
        if isinstance(ip, str) and ip.strip():
            self.totalips.add(ip.strip())

    def _add_asn(self, asn: str | int | None) -> None:
        if asn is None:
            return
        asn_value = str(asn).strip()
        if asn_value:
            self.asns.add(asn_value)

    def _collect_hosts_from_value(self, value) -> None:
        if isinstance(value, str):
            self._add_host(value.split()[0].rstrip('.'))
            return
        if isinstance(value, list):
            for item in value:
                self._collect_hosts_from_value(item)
            return
        if isinstance(value, dict):
            self._add_host(value.get('domain'))
            self._add_host(value.get('hostname'))
            self._add_host(value.get('subdomain_name'))
            for nested_value in value.values():
                self._collect_hosts_from_value(nested_value)

    async def do_search(self) -> None:
        # https://www.criminalip.io/developer/api/post-domain-scan
        # https://www.criminalip.io/developer/api/get-domain-status-id
        # https://www.criminalip.io/developer/api/get-v2-domain-report-id
        url = 'https://api.criminalip.io/v1/domain/scan'
        data = f'{{"query": "{self.word}"}}'
        # print(f'Current key: {self.key}')
        user_agent = Core.get_user_agent()
        response = await AsyncFetcher.post_fetch(
            url,
            json=True,
            headers={'User-Agent': user_agent, 'x-api-key': f'{self.key}'},
            data=data,
            proxy=self.proxy,
        )
        # print(f'My response: {response}')
        # Expected response format:
        # {'data': {'scan_id': scan_id}, 'message': 'api success', 'status': 200}
        if not isinstance(response, dict):
            print(f'An error has occurred searching criminalip dumping response: {response}')
            return
        if response.get('status') != 200:
            print(f'An error has occurred searching criminalip dumping response: {response}')
            return

        scan_id = response.get('data', {}).get('scan_id')
        if scan_id is None:
            print(f'CriminalIP did not return a scan_id, dumping response: {response}')
            return

        scan_percentage = 0
        counter = 0
        status = {}
        while scan_percentage != 100:
            status_url = f'https://api.criminalip.io/v1/domain/status/{scan_id}'
            status_response = await AsyncFetcher.fetch_all(
                [status_url],
                json=True,
                headers={'User-Agent': user_agent, 'x-api-key': f'{self.key}'},
                proxy=self.proxy,
            )
            status = status_response[0] if isinstance(status_response, list) and len(status_response) > 0 else {}
            if not isinstance(status, dict):
                print(f'CriminalIP status response is malformed dumping data: {status_response}')
                return
            if status.get('status') != 200:
                print(f'CriminalIP status check failed dumping data: status_response: {status}')
                return

            # Expected format:
            # {"data": {"scan_percentage": 100}, "message": "api success", "status": 200}
            scan_percentage = status.get('data', {}).get('scan_percentage')
            if scan_percentage is None:
                print(f'CriminalIP status did not include scan_percentage dumping data: {status}')
                return
            if scan_percentage == 100:
                break
            if scan_percentage == -2:
                print(f'CriminalIP failed to scan: {self.word} does not exist, verify manually')
                print(f'Dumping data: scan_response: {response} status_response: {status}')
                return
            if scan_percentage == -1:
                print(f'CriminalIP scan failed dumping data: scan_response: {response} status_response: {status}')
                return
            # Wait for scan to finish
            if counter >= 5:
                await asyncio.sleep(20 * get_delay())
            else:
                await asyncio.sleep(10 * get_delay())
            counter += 1
            if counter == 10:
                print(
                    'Ten iterations have occurred in CriminalIP waiting for scan to finish, returning to prevent infinite loop.'
                )
                print(f'Verify results manually on CriminalIP dumping data: scan_response: {response} status_response: {status}')
                return

        report_url = f'https://api.criminalip.io/v2/domain/report/{scan_id}'
        scan_response = await AsyncFetcher.fetch_all(
            [report_url],
            json=True,
            headers={'User-Agent': user_agent, 'x-api-key': f'{self.key}'},
            proxy=self.proxy,
        )
        scan = scan_response[0] if isinstance(scan_response, list) and len(scan_response) > 0 else {}
        if not isinstance(scan, dict):
            print(f'CriminalIP report response is malformed dumping data: {scan_response}')
            return
        if scan.get('status') != 200:
            print(f'CriminalIP report request failed dumping data: {scan}')
            return

        # json_formatted_str = json.dumps(scan, indent=2)
        # print(json_formatted_str)
        try:
            await self.parser(scan)
        except Exception as e:
            print(f'An exception occurred while parsing criminalip result: {e}')
            print('Dumping json: ')
            print(scan)

    async def parser(self, jlines):
        # TODO when new scope field is added to parse lines for potential new scope!
        # TODO map as_name to asn for asn data
        # TODO determine if worth storing interesting urls
        if not isinstance(jlines, dict) or 'data' not in jlines.keys() or not isinstance(jlines['data'], dict):
            print(f'Error with criminalip data, dumping: {jlines}')
            return
        data = jlines['data']

        for cert in data.get('certificates', []):
            # print(f'Current cert: {cert}')
            if isinstance(cert, dict):
                self._add_host(cert.get('subject'))

        for connected_domain in data.get('connected_domain_subdomain', []):
            try:
                if not isinstance(connected_domain, dict):
                    continue
                main_domain = connected_domain.get('main_domain', {}).get('domain')
                if main_domain is not None:
                    self._add_host(main_domain)
                subdomains = [sub.get('domain') for sub in connected_domain.get('subdomains', []) if isinstance(sub, dict)]
                for sub in subdomains:
                    # print(f'Current sub: {sub}')
                    self._add_host(sub)
            except Exception as e:
                print(f'An exception has occurred: {e}')
                print(f'Main line: {connected_domain}')

        for ip_info in data.get('connected_ip_info', []):
            if not isinstance(ip_info, dict):
                continue
            self._add_asn(ip_info.get('asn'))
            domains = [sub.get('domain') for sub in ip_info.get('domain_list', []) if isinstance(sub, dict)]
            for sub in domains:
                if self._add_host(sub):
                    self._add_ip(ip_info.get('ip'))

        for subdomain in data.get('subdomains', []):
            if isinstance(subdomain, dict):
                self._add_host(subdomain.get('subdomain_name'))
                self._add_host(subdomain.get('domain'))

        for cookie in data.get('cookies', []):
            if isinstance(cookie, dict):
                cookie_domain = cookie.get('domain')
                if isinstance(cookie_domain, str):
                    self._add_host(cookie_domain.lstrip('.'), include_root=False)

        for connected_ip in data.get('connected_ip', []):
            if isinstance(connected_ip, dict):
                self._add_ip(connected_ip.get('ip'))

        for mapped_ip in data.get('mapped_ip', []):
            if isinstance(mapped_ip, dict):
                self._add_ip(mapped_ip.get('ip'))

        for country in data.get('country', []):
            if not isinstance(country, dict):
                continue
            if self._add_host(country.get('domain')):
                for ip in country.get('mapped_ips', []):
                    if isinstance(ip, dict):
                        self._add_ip(ip.get('ip'))

        for k, v in data.get('dns_record', {}).items():
            if k == 'dns_record_type_a':
                dns_a_record = data.get('dns_record', {}).get(k, {})
                if not isinstance(dns_a_record, dict):
                    continue
                for ip in dns_a_record.get('ipv4', []):
                    if isinstance(ip, dict):
                        self._add_ip(ip.get('ip'))
                    elif isinstance(ip, str):
                        self._add_ip(ip)
                for ip in dns_a_record.get('ipv6', []):
                    if isinstance(ip, dict):
                        self._add_ip(ip.get('ip'))
                    elif isinstance(ip, str):
                        self._add_ip(ip)
            elif isinstance(v, list):
                self._collect_hosts_from_value(v)
            elif isinstance(v, dict):
                self._collect_hosts_from_value(v)

        for domain_list in data.get('domain_list', []):
            if not isinstance(domain_list, dict):
                continue
            self._add_asn(domain_list.get('asn'))
            domains = [sub.get('domain') for sub in domain_list.get('domain_list', []) if isinstance(sub, dict)]
            for sub in domains:
                if self._add_host(sub):
                    self._add_ip(domain_list.get('ip'))

        for html_page_links in data.get('html_page_link_domains', []):
            if not isinstance(html_page_links, dict):
                continue
            if self._add_host(html_page_links.get('domain')):
                for ip in html_page_links.get('mapped_ips', []):
                    if isinstance(ip, dict):
                        self._add_ip(ip.get('ip'))

        # TODO combine data['links'] and data['network_logs'] urls into one list for one run through
        for link in data.get('links', []):
            if isinstance(link, dict):
                self._add_host_from_url(link.get('url'))

        network_logs = data.get('network_logs', [])
        if isinstance(network_logs, dict):
            network_logs = network_logs.get('data', [])
        if not isinstance(network_logs, list):
            network_logs = []
        for log in network_logs:
            if not isinstance(log, dict):
                continue
            self._add_host_from_url(log.get('url'))
            self._add_asn(log.get('as_number'))
            ip_port = log.get('ip_port')
            if isinstance(ip_port, str) and ':' in ip_port:
                self._add_ip(ip_port.rsplit(':', 1)[0])

        for redirects in data.get('page_redirections', []):
            if isinstance(redirects, dict):
                redirects = [redirects]
            if not isinstance(redirects, list):
                continue
            for redirect in redirects:
                if isinstance(redirect, dict):
                    self._add_host_from_url(redirect.get('url'))

        self.totalhosts = {host[4:] if host.startswith('www.') else host for host in self.totalhosts if '*.' + self.word != host}

        # print(f'hostnames: {self.totalhosts}')
        # print(f'asns: {self.asns}')
        # print(f'ips: {self.totalips}')

    async def get_asns(self) -> set:
        return self.asns

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
