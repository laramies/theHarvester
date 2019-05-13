import theHarvester.discovery.DNS as DNS
import theHarvester.discovery.IPy as IPy
import os
import sys


class dns_reverse():

    def __init__(self, range, verbose=True):
        self.range = range
        self.iplist = ''
        self.results = []
        self.verbose = verbose
        try:
            DNS.ParseResolvConf('/etc/resolv.conf')
            nameserver = DNS.defaults['server'][0]
        except:
            print('Error in DNS resolvers')
            sys.exit()

    def run(self, host):
        a = host.split('.')
        a.reverse()
        s = '.'
        b = s.join(a) + '.in-addr.arpa'
        nameserver = DNS.defaults['server'][0]
        if self.verbose:
            ESC = chr(27)
            sys.stdout.write(ESC + '[2K' + ESC + '[G')
            sys.stdout.write('\r\t' + host)
            sys.stdout.flush()
        try:
            name = DNS.Base.DnsRequest(b, qtype='ptr').req().answers[0]['data']
            return host + ':' + name
        except:
            pass

    def get_ip_list(self, ips):
        """Generates the list of IPs to reverse"""
        try:
            list = IPy.IP(ips)
        except:
            print('Error in IP format, check the input and try again. (Eg. 192.168.1.0/24)')
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
        self.nameserver = dnsserver
        self.file = 'wordlists/dns-big.txt'
        self.subdo = False
        self.verbose = verbose
        try:
            fileDir = os.path.dirname(os.path.realpath('__file__'))
            res_path = os.path.join(fileDir,'lib/resolvers.txt')
            with open(res_path) as f:
                self.resolvers = f.read().splitlines()
        except Exception:
            print("Resolvers file can't be open.")
        try:
            f = open(self.file, 'r')
        except:
            print('Error opening DNS dictionary file.')
            sys.exit()
        self.list = f.readlines()

    def getdns(self, domain):
        DNS.ParseResolvConf('/etc/resolv.conf')
        dom = domain
        if self.subdo is True:
            dom = domain.split('.')
            dom.pop(0)
            rootdom = '.'.join(dom)
        else:
            rootdom = dom
        if self.nameserver == "":
            try:
                r = DNS.Request(rootdom, qtype='SOA').req()
                primary, email, serial, refresh, retry, expire, minimum = r.answers[
                    0]['data']
                test = DNS.Request(
                    rootdom,
                    qtype='NS',
                    server=primary,
                    aa=1).req()

            except Exception as e:
                print(e)
            try:
                # Check if variable is defined.
                test
            except NameError:
                print('Error, test is not defined.')
                sys.exit()
            if test.header['status'] != 'NOERROR':
                print('[!] Error')
                sys.exit()
            self.nameserver = test.answers[0]['data']
        elif self.nameserver == 'local':
            self.nameserver = nameserver
        return self.nameserver

    def run(self, host):
        if self.nameserver == "":
            self.nameserver = self.getdns(self.domain)
            print('\n\033[94m[-] Using DNS server: ' + self.nameserver + '\033[1;33;40m\n')

        hostname = str(host.split('\n')[0]) + '.' + str(self.domain)
        if self.verbose:
            ESC = chr(27)
            sys.stdout.write(ESC + '[2K' + ESC + '[G')
            sys.stdout.write('\r' + hostname)
            sys.stdout.flush()
        try:
            test = DNS.Request(
                hostname,
                qtype='a',
                server=self.nameserver).req(
            )
            # TODO FIX test is sometimes not getting answers and leads to an indexing error.
            hostip = test.answers[0]['data']
            return hostname + ':' + hostip
        except Exception:
            pass

    def process(self):
        results = []
        for x in self.list:
            host = self.run(x)
            if host is not None:
                print(' : ' + host.split(':')[1])
                results.append(host)
        return results


class dns_tld():

    def __init__(self, domain, dnsserver, verbose=False):
        self.domain = domain
        self.nameserver = dnsserver
        self.subdo = False
        self.verbose = verbose
        # Updated from http://data.iana.org/TLD/tlds-alpha-by-domain.txt
        self.tlds = [
            'ac', 'academy', 'ad', 'ae', 'aero', 'af', 'ag', 'ai', 'al', 'am', 'an', 'ao', 'aq', 'ar', 'arpa', 'as',
            'asia', 'at', 'au', 'aw', 'ax', 'az', 'ba', 'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bike', 'biz', 'bj',
            'bm', 'bn', 'bo', 'br', 'bs', 'bt', 'builders', 'buzz', 'bv', 'bw', 'by', 'bz', 'ca', 'cab', 'camera',
            'camp', 'careers', 'cat', 'cc', 'cd', 'center', 'ceo', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'clothing',
            'cm', 'cn', 'co', 'codes', 'coffee', 'com', 'company', 'computer', 'construction', 'contractors', 'coop',
            'cr', 'cu', 'cv', 'cw', 'cx', 'cy', 'cz', 'de', 'diamonds', 'directory', 'dj', 'dk', 'dm', 'do',
            'domains', 'dz', 'ec', 'edu', 'education', 'ee', 'eg', 'email', 'enterprises', 'equipment', 'er', 'es',
            'estate', 'et', 'eu', 'farm', 'fi', 'fj', 'fk', 'florist', 'fm', 'fo', 'fr', 'ga', 'gallery', 'gb', 'gd',
            'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'glass', 'gm', 'gn', 'gov', 'gp', 'gq', 'gr', 'graphics', 'gs', 'gt',
            'gu', 'guru', 'gw', 'gy', 'hk', 'hm', 'hn', 'holdings', 'holiday', 'house', 'hr', 'ht', 'hu', 'id', 'ie',
            'il', 'im', 'immobilien', 'in', 'info', 'institute', 'int', 'international', 'io', 'iq', 'ir', 'is', 'it',
            'je', 'jm', 'jo', 'jobs', 'jp', 'kaufen', 'ke', 'kg', 'kh', 'ki', 'kitchen', 'kiwi', 'km', 'kn', 'kp',
            'kr', 'kw', 'ky', 'kz', 'la', 'land', 'lb', 'lc', 'li', 'lighting', 'limo', 'lk', 'lr', 'ls', 'lt', 'lu',
            'lv', 'ly', 'ma', 'management', 'mc', 'md', 'me', 'menu', 'mg', 'mh', 'mil', 'mk', 'ml', 'mm', 'mn', 'mo',
            'mobi', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'museum', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'name', 'nc',
            'ne', 'net', 'nf', 'ng', 'ni', 'ninja', 'nl', 'no', 'np', 'nr', 'nu', 'nz', 'om', 'onl', 'org', 'pa', 'pe',
            'pf', 'pg', 'ph', 'photography', 'photos', 'pk', 'pl', 'plumbing', 'pm', 'pn', 'post', 'pr', 'pro', 'ps',
            'pt', 'pw', 'py', 'qa', 're', 'recipes', 'repair', 'ro', 'rs', 'ru', 'ruhr', 'rw', 'sa', 'sb', 'sc', 'sd',
            'se', 'sexy', 'sg', 'sh', 'shoes', 'si', 'singles', 'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'solar',
            'solutions', 'sr', 'st', 'su', 'support', 'sv', 'sx', 'sy', 'systems', 'sz', 'tattoo', 'tc', 'td',
            'technology', 'tel', 'tf', 'tg', 'th', 'tips', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'today', 'tp', 'tr',
            'training', 'travel', 'tt', 'tv', 'tw', 'tz', 'ua', 'ug', 'uk', 'uno', 'us', 'uy', 'uz', 'va', 'vc',
            've', 'ventures', 'vg', 'vi', 'viajes', 'vn', 'voyage', 'vu', 'wang', 'wf', 'wien', 'ws', 'xxx', 'ye',
            'yt', 'za', 'zm', 'zw']

    def getdns(self, domain):
        dom = domain
        if self.subdo is True:
            dom = domain.split('.')
            dom.pop(0)
            rootdom = '.'.join(dom)
        else:
            rootdom = dom
        if self.nameserver is False:
            r = DNS.Request(rootdom, qtype='SOA').req()
            primary, email, serial, refresh, retry, expire, minimum = r.answers[
                0]['data']
            test = DNS.Request(rootdom, qtype='NS', server=primary, aa=1).req()
            if test.header['status'] != 'NOERROR':
                print('Error')
                sys.exit()
            self.nameserver = test.answers[0]['data']
        elif self.nameserver == 'local':
            self.nameserver = nameserver
        return self.nameserver

    def run(self, tld):
        self.nameserver = self.getdns(self.domain)
        hostname = self.domain.split('.')[0] + '.' + tld
        if self.verbose:
            ESC = chr(27)
            sys.stdout.write(ESC + '[2K' + ESC + '[G')
            sys.stdout.write('\r\tSearching for: ' + hostname)
            sys.stdout.flush()
        try:
            test = DNS.Request(
                hostname,
                qtype='a',
                server=self.nameserver).req(
            )
            hostip = test.answers[0]['data']
            return hostip + ':' + hostname
        except Exception:
            pass

    def process(self):
        results = []
        for x in self.tlds:
            host = self.run(x)
            if host is not None:
                results.append(host)
        return results
