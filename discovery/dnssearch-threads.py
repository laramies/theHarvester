import IPy
import DNS
import string
import socket
import sys


class dns_reverse():

    def __init__(self, range, verbose=True):
        self.range = range
        self.iplist = ''
        self.results = []
        self.verbose = verbose
        try:
            DNS.ParseResolvConf("/etc/resolv.conf")
            nameserver = DNS.defaults['server'][0]
        except:
            print "Error in DNS resolvers"
            sys.exit()

    def run(self, host):
        a = string.split(host, '.')
        a.reverse()
        b = string.join(a, '.') + '.in-addr.arpa'
        nameserver = DNS.defaults['server'][0]
        if self.verbose:
            ESC = chr(27)
            sys.stdout.write(ESC + '[2K' + ESC + '[G')
            sys.stdout.write("\r" + host)
            sys.stdout.flush()
        try:
            name = DNS.Base.DnsRequest(b, qtype='ptr').req().answers[0]['data']
            return host + ":" + name
        except:
            pass

    def get_ip_list(self, ips):
        """Generates the list of ips to reverse"""
        try:
            list = IPy.IP(ips)
        except:
            print "Error in IP format, check the input and try again. (Eg. 192.168.1.0/24)"
            sys.exit()
        name = []
        for x in list:
            name.append(str(x))
        return name

    def list(self):
        self.iplist = self.get_ip_list(self.range)
        return self.iplist

    def process(self):
        for x in self.iplist:
            host = self.run(x)
            if host is not None:
                self.results.append(host)
        return self.results


class dns_force():

    def __init__(self, domain, dnsserver, verbose=False):
        self.domain = domain
        self.server = dnsserver
        self.file = "dns-names.txt"
        self.subdo = False
        self.verbose = verbose
        try:
            f = open(self.file, "r")
        except:
            print "Error opening dns dictionary file"
            sys.exit()
        self.list = f.readlines()

    def getdns(self, domain):
        DNS.ParseResolvConf("/etc/resolv.conf")
        nameserver = DNS.defaults['server'][0]
        dom = domain
        if self.subdo == True:
            dom = domain.split(".")
            dom.pop(0)
            rootdom = ".".join(dom)
        else:
            rootdom = dom
        if self.server == False:
            r = DNS.Request(rootdom, qtype='SOA').req()
            primary, email, serial, refresh, retry, expire, minimum = r.answers[
                0]['data']
            test = DNS.Request(rootdom, qtype='NS', server=primary, aa=1).req()
        if test.header['status'] != "NOERROR":
            print "Error"
            sys.exit()
        self.nameserver = test.answers[0]['data']
        return self.nameserver

    def run(self, host):
        self.nameserver = self.getdns(self.domain)
        hostname = str(host.split("\n")[0]) + "." + str(self.domain)
        # nameserver=DNS.defaults['server'][0]
        if self.verbose:
            ESC = chr(27)
            sys.stdout.write(ESC + '[2K' + ESC + '[G')
            sys.stdout.write("\r" + hostname)
            sys.stdout.flush()
        try:
            test = DNS.Request(
                hostname,
                qtype='a',
                server=self.nameserver).req(
            )
            hostip = test.answers[0]['data']
            return hostip + ":" + hostname
        except Exception as e:
            pass

    def process(self):
        results = []
        for x in self.list:
            host = self.run(x)
            if host is not None:
                results.append(host)
        return results
