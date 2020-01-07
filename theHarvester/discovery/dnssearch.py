import sys
import dns.resolver
import dns.reversename

# TODO: need big focus on performance and results parsing, now does the basic.


class DnsForce:

    def __init__(self, domain, dnsserver, verbose=False):
        self.domain = domain
        self.subdo = False
        self.verbose = verbose
        try:
            with open('wordlists/dns-names.txt', 'r') as file:
                self.list = file.readlines()
        except FileNotFoundError:
            with open('/etc/theHarvester/dns-names.txt', 'r') as file:
                self.list = file.readlines()

    def run(self, host):
        hostname = str(host.split('\n')[0]) + '.' + str(self.domain)
        if self.verbose:
            esc = chr(27)
            sys.stdout.write(esc + '[2K' + esc + '[G')
            sys.stdout.write('\r' + hostname + ' - ')
            sys.stdout.flush()
        try:
            answer = dns.resolver.query(hostname, 'A')
            print(answer.canonical_name)
            return answer.canonical_name  # TODO: need rework all this results

        except Exception:
            pass

    def process(self):
        results = []
        for entry in self.list:
            host = self.run(entry)
            if host is not None:
                # print(' : ' + host.split(':')[1])
                results.append(host)
        return results


class DnsReverse:

    def __init__(
            self,
            iprange: str,
            verbose: bool = False) -> None:
        self.iprange = iprange
        self.verbose = verbose

    def list(
            self) -> list:
        prefix = '.'.join(
            self.iprange.split('.')[:-1])
        self.list = [prefix + '.' + str(i) for i in range(256)]

    def run(
            self,
            ip: str) -> str:
        if self.verbose:
            esc = chr(27)
            sys.stdout.write(esc + '[2K' + esc + '[G')
            sys.stdout.write('\r' + ip + ' - ')
            sys.stdout.flush()
        try:
            dns_record_from_ip_answer = dns.reversename.from_address(ip)
            ptr_record_answer = dns.resolver.query(dns_record_from_ip_answer, 'PTR')
            a_record_answer = dns.resolver.query(ptr_record_answer[0].to_text(), 'A')
            print(a_record_answer.canonical_name)
            return str(a_record_answer.canonical_name)

        except Exception:
            pass

    def process(
            self) -> list:
        results = []
        for entry in self.list:
            host = self.run(entry)
            if host is not None:
                # print(' : ' + host.split(':')[1])
                results.append(host)
        return results
