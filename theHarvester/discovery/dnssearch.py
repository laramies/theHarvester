# -*- coding: utf-8 -*-

"""
============
DNS Browsing
============

Explore the space around known hosts & ips for extra catches.
"""

from __future__ import absolute_import, division, print_function

import asyncio
import re
import sys

from aiodns import DNSResolver
from ipaddress import IPv4Address, IPv4Network
from typing import AsyncGenerator, Awaitable, List

# TODO: need big focus on performance and results parsing, now does the basic.

#####################################################################
# DNS FORCE
#####################################################################

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

IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
PORT_REGEX = r'\d{1,5}'
NETMASK_REGEX = r'\d{1,2}|' + IP_REGEX
NETWORK_REGEX = r'\b({})(?:\:({}))?(?:\/({}))?\b'.format(
    IP_REGEX,
    PORT_REGEX,
    NETMASK_REGEX)

def serialize_ip_range(
        ip: str,
        netmask: str = '24') -> str:
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
    __ip = __ip_matches.group(1)
    __port = __ip_matches.group(2)
    __netmask = netmask if netmask else __ip_matches.group(3)
    if __ip and __netmask:
        return str(IPv4Network('{}/{}'.format(__ip, __netmask), strict=False))
    elif __ip:
        return str(IPv4Network('{}/{}'.format(__ip, '24'), strict=False))
    else:   # invalid input ip
        return ''

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
    try:
        __network = IPv4Network(iprange, strict=False)
        return [__address.exploded for __address in __network.hosts()]
    except Exception:
        return []

async def reverse_single_ip(
        ip: str,
        resolver: DNSResolver) -> Awaitable[str]:
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
    try:
        __host = await resolver.gethostbyaddr(ip)
        return __host.name if __host else ''
    except Exception:
        return ''

async def reverse_all_ips_in_range(
        iprange: str,
        verbose: bool = False) -> AsyncGenerator[str, None]:
    """
    Reverse all the IPs stored in a network range.

    Parameters
    ----------
    iprange: str.
        An IPv4 range formated as 'x.x.x.x/y'.
        The last 2 digits of the ip can be set to anything,
        they will be ignored.
    verbose: bool.
        Print the progress or not.

    Returns
    -------
    out: list.
        The list of all the found CNAME records.
    """
    __resolver = DNSResolver(timeout=4)
    for ip in list_ips_in_network_range(iprange):
        # Display the current query
        if verbose:
            sys.stdout.write(chr(27) + '[2K' + chr(27) + '[G')
            sys.stdout.write('\r' + ip + ' - ')
            sys.stdout.flush()

        # Reverse the ip
        __host = await reverse_single_ip(ip=ip, resolver=__resolver)

        # Output the results
        if __host is not None and __host:
            print(__host)
            yield __host
