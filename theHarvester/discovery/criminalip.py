import asyncio
from urllib.parse import urlparse

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.core import AsyncFetcher, Core


class SearchCriminalIP:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.asns: set = set()
        self.key = Core.criminalip_key()
        if self.key is None:
            raise MissingKey('criminalip')
        self.proxy = False

    async def do_search(self) -> None:
        # https://www.criminalip.io/developer/api/post-domain-scan
        # https://www.criminalip.io/developer/api/get-domain-status-id
        # https://www.criminalip.io/developer/api/get-domain-report-id
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
        if 'status' in response.keys():
            status = response['status']
            if status != 200:
                print(f'An error has occurred searching criminalip dumping response: {response}')
            else:
                scan_id = response['data']['scan_id']
                scan_percentage = 0
                counter = 0
                while scan_percentage != 100:
                    status_url = f'https://api.criminalip.io/v1/domain/status/{scan_id}'
                    status_response = await AsyncFetcher.fetch_all(
                        [status_url],
                        json=True,
                        headers={'User-Agent': user_agent, 'x-api-key': f'{self.key}'},
                        proxy=self.proxy,
                    )
                    status = status_response[0]
                    # print(f'Status response: {status}')
                    # Expected format:
                    # {"data": {"scan_percentage": 100}, "message": "api success", "status": 200}
                    scan_percentage = status['data']['scan_percentage']
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
                        print(
                            f'Verify results manually on CriminalIP dumping data: scan_response: {response} status_response: {status}'
                        )
                        return

                report_url = f'https://api.criminalip.io/v1/domain/report/{scan_id}'
                scan_response = await AsyncFetcher.fetch_all(
                    [report_url],
                    json=True,
                    headers={'User-Agent': user_agent, 'x-api-key': f'{self.key}'},
                    proxy=self.proxy,
                )
                scan = scan_response[0]
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
        if 'data' not in jlines.keys():
            print(f'Error with criminalip data, dumping: {jlines}')
            return
        data = jlines['data']
        for cert in data['certificates']:
            # print(f'Current cert: {cert}')
            if cert['subject'].endswith('.' + self.word):
                self.totalhosts.add(cert['subject'])

        for connected_domain in data['connected_domain_subdomain']:
            try:
                main_domain = connected_domain['main_domain']['domain']
                subdomains = [sub['domain'] for sub in connected_domain['subdomains']]
                if main_domain.endswith('.' + self.word):
                    self.totalhosts.add(main_domain)
                for sub in subdomains:
                    # print(f'Current sub: {sub}')
                    if sub.endswith('.' + self.word):
                        self.totalhosts.add(sub)
            except Exception as e:
                print(f'An exception has occurred: {e}')
                print(f'Main line: {connected_domain}')

        for ip_info in data['connected_ip_info']:
            self.asns.add(str(ip_info['asn']))
            domains = [sub['domain'] for sub in ip_info['domain_list']]
            for sub in domains:
                if sub.endswith('.' + self.word):
                    self.totalhosts.add(sub)
                    self.totalips.add(ip_info['ip'])

        for cookie in data['cookies']:
            if cookie['domain'] != '.' + self.word and cookie['domain'].endswith('.' + self.word):
                self.totalhosts.add(cookie['domain'])

        for country in data['country']:
            if country['domain'].endswith('.' + self.word):
                self.totalhosts.add(country['domain'])
                for ip in country['mapped_ips']:
                    self.totalips.add(ip['ip'])

        for k, v in data['dns_record'].items():
            if k == 'dns_record_type_a':
                for ip in data['dns_record'][k]['ipv4']:
                    self.totalips.add(ip['ip'])
            else:
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, list):
                            for subitem in item:
                                if subitem.endswith('.' + self.word):
                                    self.totalhosts.add(subitem)
                        else:
                            if item.endswith('.' + self.word):
                                self.totalhosts.add(item)

        for domain_list in data['domain_list']:
            self.asns.add(str(domain_list['asn']))
            domains = [sub['domain'] for sub in domain_list['domain_list']]
            for sub in domains:
                if sub.endswith('.' + self.word):
                    self.totalhosts.add(sub)
                    self.totalips.add(domain_list['ip'])

        for html_page_links in data['html_page_link_domains']:
            domain = html_page_links['domain']
            if domain.endswith('.' + self.word):
                self.totalhosts.add(domain)
                for ip in html_page_links['mapped_ips']:
                    self.totalips.add(ip['ip'])

        # TODO combine data['links'] and data['network_logs'] urls into one list for one run through
        for link in data['links']:
            url = link['url']
            parsed_url = urlparse(url)
            netloc = parsed_url.netloc
            if self.word in netloc:
                if (':' in netloc and netloc.split(':')[0].endswith(self.word)) or netloc.endswith(self.word):
                    self.totalhosts.add(netloc)

        for log in data['network_logs']:
            url = log['url']
            parsed_url = urlparse(url)
            netloc = parsed_url.netloc
            if self.word in netloc:
                if (':' in netloc and netloc.split(':')[0].endswith(self.word)) or netloc.endswith(self.word):
                    self.totalhosts.add(netloc)
                    self.asns.add(str(log['as_number']))

        for redirects in data['page_redirections']:
            for redirect in redirects:
                url = redirect['url']
                parsed_url = urlparse(url)
                netloc = parsed_url.netloc
                if self.word in netloc:
                    if (':' in netloc and netloc.split(':')[0].endswith(self.word)) or netloc.endswith(self.word):
                        self.totalhosts.add(netloc)

        self.totalhosts = {host.replace('www.', '') for host in self.totalhosts if '*.' + self.word != host}

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
