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
    """
    Find all the IPs in a range associated with a CNAME.
    """

    def __init__(
            self,
            iprange: str,
            verbose: bool = False) -> None:
        """
        Initialize.

        Parameters
        ----------
        iprange: str.
            An IPv4 range formated as 'x.x.x.x/y'
        verbose: bool.
            Print the progress or not.

        Returns
        -------
        out: None.
        """
        self.iprange = iprange
        self.verbose = verbose

    def list(
            self) -> list:
        """
        List all the IPs in the range.
        They are stored in self.list.

        Parameters
        ----------

        Returns
        -------
        out: None.
        """
        prefix = '.'.join(
            self.iprange.split('.')[:-1])
        self.list = [prefix + '.' + str(i) for i in range(256)]

    def run(
            self,
            ip: str) -> str:
        """
        Reverse a single IP and output the linked CNAME, if it exists.

        Parameters
        ----------
        ip: str.
            The IP to reverse.

        Returns
        -------
        out: str.
            The corresponding CNAME or None.
        """
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
        """
        Reverse all the IPs stored in 'self.list'.

        Parameters
        ----------

        Returns
        -------
        out: list.
            The list of all the found CNAME records.
        """
        results = []
        for entry in self.list:
            host = self.run(entry)
            if host is not None:
                # print(' : ' + host.split(':')[1])
                results.append(host)
        return results
