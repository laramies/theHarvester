import sys
import dns.resolver

# TODO: need big focus on performance and results parsing, now does the basic.


class DnsForce:

    def __init__(self, domain, dnsserver, verbose=False):
        self.domain = domain
        self.file = 'wordlists/dns-names.txt'
        self.subdo = False
        self.verbose = verbose
        try:
            f = open(self.file, 'r')
        except Exception:
            print('Error opening DNS dictionary file.')
            sys.exit()
        self.list = f.readlines()

    def run(self, host):
        hostname = str(host.split('\n')[0]) + '.' + str(self.domain)
        if self.verbose:
            ESC = chr(27)
            sys.stdout.write(ESC + '[2K' + ESC + '[G')
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
