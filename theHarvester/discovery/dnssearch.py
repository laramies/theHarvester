# -*- coding: utf-8 -*-

"""
============
DNS Browsing
============

Explore the space around known hosts & ips for extra catches.
"""

import re
import sys

from aiodns import DNSResolver
from ipaddress import IPv4Network
from typing import Callable, List, Optional
from theHarvester.lib import hostchecker


#####################################################################
# DNS FORCE
#####################################################################


class DnsForce:

    def __init__(self, domain, dnsserver, verbose: bool = False) -> None:
        self.domain = domain
        self.subdo = False
        self.verbose = verbose
        # self.dnsserver = [dnsserver] if isinstance(dnsserver, str) else dnsserver
        self.dnsserver = list(map(str, dnsserver.split(','))) if isinstance(dnsserver, str) else dnsserver
        try:
            with open('/etc/theHarvester/wordlists/dns-names.txt', 'r') as file:
                self.list = file.readlines()
        except FileNotFoundError:
            try:
                with open('/usr/local/etc/theHarvester/wordlists/dns-names.txt', 'r') as file:
                    self.list = file.readlines()
            except FileNotFoundError:
                with open('wordlists/dns-names.txt', 'r') as file:
                    self.list = file.readlines()
        self.domain = domain.replace('www.', '')
        self.list = [f'{word.strip()}.{self.domain}' for word in self.list]

    async def run(self):
        print(f'Starting DNS brute forcing with {len(self.list)} words')
        checker = hostchecker.Checker(
            self.list) if self.dnsserver == [] or self.dnsserver == "" or self.dnsserver is None \
            else hostchecker.Checker(self.list, nameserver=self.dnsserver)
        hosts, ips = await checker.check()
        return hosts, ips


#####################################################################
# DNS REVERSE
#####################################################################


IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
PORT_REGEX = r'\d{1,5}'
NETMASK_REGEX: str = r'\d{1,2}|' + IP_REGEX
NETWORK_REGEX: str = r'\b({})(?:\:({}))?(?:\/({}))?\b'.format(
    IP_REGEX,
    PORT_REGEX,
    NETMASK_REGEX)


def serialize_ip_range(ip: str, netmask: str = '24') -> str:
    """
    Serialize a network range in a constant format, 'x.x.x.x/y'.

    Parameters
    ----------
    ip: str.
        A serialized ip in the format 'x.x.x.x'.
        Extra information like port (':z') or subnet ('/n')
        will be ignored.
    netmask: str.
        The subnet subdivision, represented by a 2 digit netmask.

    Returns
    -------
    out: str.
        The network OSI address, like '192.168.0.0/24'.
    """
    __ip_matches = re.search(NETWORK_REGEX, ip, re.IGNORECASE)
    if __ip_matches and __ip_matches.groups():
        __ip = __ip_matches.group(1)
        __netmask = netmask if netmask else __ip_matches.group(3)
        if __ip and __netmask:
            return str(IPv4Network('{}/{}'.format(__ip, __netmask), strict=False))
        elif __ip:
            return str(IPv4Network('{}/{}'.format(__ip, '24'), strict=False))

    # invalid input ip
    return ''


def list_ips_in_network_range(iprange: str) -> List[str]:
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
    try:
        __network = IPv4Network(iprange, strict=False)
        return [__address.exploded for __address in __network.hosts()]
    except Exception:
        return []


async def reverse_single_ip(ip: str, resolver: DNSResolver) -> str:
    """
    Reverse a single IP and output the linked CNAME, if it exists.
        Parameters
        ----------
        :param ip:  IP address to reverse
        :param resolver: DNS server to use

        Returns
        -------
        :return str: with the corresponding CNAME or None
    """
    try:
        __host = await resolver.gethostbyaddr(ip)
        return __host.name if __host else ''
    except Exception:
        return ''


async def reverse_all_ips_in_range(iprange: str, callback: Callable, nameservers: Optional[List[str]] = None) -> None:
    """
    Reverse all the IPs stored in a network range.
    All the queries are made concurrently.

    Parameters
    ----------
    iprange: str.
        An IPv4 range formatted as 'x.x.x.x/y'.
        The last 2 digits of the ip can be set to anything,
        they will be ignored.
    callback: Callable.
        Arbitrary postprocessing function.
    nameservers: List[str].
        Optional list of DNS servers.

    Returns
    -------
    out: None.
    """
    __resolver = DNSResolver(timeout=4, nameservers=nameservers)
    for __ip in list_ips_in_network_range(iprange):
        log_query(__ip)
        __host = await reverse_single_ip(ip=__ip, resolver=__resolver)
        callback(__host)
        log_result(__host)


#####################################################################
# IO
#####################################################################


def log_query(ip: str) -> None:
    """
    Display the current query in the console.

    Parameters
    ----------
    ip: str.
        Queried ip.

    Results
    -------
    out: None.
    """
    sys.stdout.write(chr(27) + '[2K' + chr(27) + '[G')
    sys.stdout.write('\r' + ip + ' - ')
    sys.stdout.flush()


def log_result(host: str) -> None:
    """
    Display the query result in the console.

    Parameters
    ----------
    host: str.
        Host name returned by the DNS query.

    Results
    -------
    out: None.
    """
    if host:
        print(host)


def generate_postprocessing_callback(target: str, **allhosts: List[str]) -> Callable:
    """
    Postprocess the query results asynchronously too, instead of waiting for
    the querying stage to be completely finished.

    Parameters
    ----------
    target: str.
        The domain wanted as TLD.
    allhosts: List.
        A collection of all the subdomains -of target- found so far.

    Returns
    -------
    out: Callable.
        A function that will update the collection of target subdomains
        when the query result is satisfying.
    """

    def append_matching_hosts(host: str) -> None:
        if host and target in host:
            for __name, __hosts in allhosts.items():
                if host not in __hosts:
                    __hosts.append(host)

    return append_matching_hosts
