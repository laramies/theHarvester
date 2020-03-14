import sys
import dns.resolver
import dns.reversename

from ipaddress import IPv4Address, IPv4Network
from typing import List

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

#####################################################################
# DNS REVERSE
#####################################################################

def list_ips_in_network_range(
        iprange: str) -> List[str]:
    """
    List all the IPs in the range.

    Parameters
    ----------
    iprange: str.
        A serialized ip range, like '1.2.3.0/24'.
        The last digit can be set to anything, it will be ignored.

    Returns
    -------
    out: list.
        The list of IPs in the range.
    """
    __network = IPv4Network(iprange, strict=False)
    return [__address.exploded for __address in __network.hosts()]

def reverse_single_ip(
        ip: str,
        verbose: bool = False) -> str:
    """
    Reverse a single IP and output the linked CNAME, if it exists.

    Parameters
    ----------
    ip: str.
        The IP to reverse.
    verbose: bool.
        Print the progress or not.

    Returns
    -------
    out: str.
        The corresponding CNAME or None.
    """
    if verbose:
        sys.stdout.write(chr(27) + '[2K' + chr(27) + '[G')
        sys.stdout.write('\r' + ip + ' - ')
        sys.stdout.flush()
    try:
        dns_record_from_ip_answer = dns.reversename.from_address(ip)
        ptr_record_answer = dns.resolver.query(dns_record_from_ip_answer, 'PTR')
        a_record_answer = dns.resolver.query(ptr_record_answer[0].to_text(), 'A')
        print(a_record_answer.canonical_name)
        return str(a_record_answer.canonical_name)
    except Exception:
        return ''

def reverse_ip_range(
        iprange: str,
        verbose: bool = False) -> List[str]:
    """
    Reverse all the IPs stored in a network range.

    Parameters
    ----------
    iprange: str.
        An IPv4 range formated as 'x.x.x.x/y'.
        The last digit can be set to anything, it will be ignored.
    verbose: bool.
        Print the progress or not.

    Returns
    -------
    out: list.
        The list of all the found CNAME records.
    """
    results = []
    for ip in list_ips_in_network_range(iprange):
        host = reverse_single_ip(ip=ip, verbose=verbose)
        if host is not None and host:
            # print(' : ' + host.split(':')[1])
            results.append(host)
    return results
