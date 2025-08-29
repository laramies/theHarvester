import ipaddress


class Parser:
    def __init__(self, word, text) -> None:
        self.word = word
        self.text = text
        self.hostnames: set = set()
        self.ips: set = set()

    async def parse_text(self) -> tuple[set, set]:
        """
        Parse SecurityTrails data and extract IPs and hostnames.
        - Supports structured dict with keys {"domain": {...}, "subdomains": {...}}
        - Also supports raw dict from either endpoint.
        - Falls back to legacy string parsing when input is a string.
        """
        # sanitize base domain
        base_domain = self.word.replace('www.', '') if 'www' in self.word else self.word

        def add_ip(value: str) -> None:
            try:
                ipaddress.ip_address(value)
                self.ips.add(value)
            except ValueError:
                raise ValueError(f'Invalid IP address provided: {value}')

        def parse_domain_dict(d: dict) -> None:
            current_dns = d.get('current_dns', {}) if isinstance(d, dict) else {}
            # IPv4
            a = current_dns.get('a') or {}
            for v in a.get('values', []) or []:
                ip = v.get('ip')
                if isinstance(ip, str):
                    add_ip(ip.strip())
            # IPv6
            aaaa = current_dns.get('aaaa') or {}
            for v in aaaa.get('values', []) or []:
                ipv6 = v.get('ipv6')
                if isinstance(ipv6, str):
                    add_ip(ipv6.strip())

        def parse_subdomains_dict(d: dict, apex: str) -> None:
            subs = d.get('subdomains') if isinstance(d, dict) else None
            if isinstance(subs, list):
                for s in subs:
                    if isinstance(s, str) and s:
                        self.hostnames.add(f'{s.strip()}.{apex}')

        # Structured dict handling
        if isinstance(self.text, dict):
            domain_dict = None
            subdomains_dict = None

            # Combined format
            if 'domain' in self.text or 'subdomains' in self.text:
                domain_dict = self.text.get('domain') if isinstance(self.text.get('domain'), dict) else None
                subdomains_dict = self.text.get('subdomains') if isinstance(self.text.get('subdomains'), dict) else None
                # Sometimes the top-level dict itself is the domain response
                if domain_dict is None:
                    domain_dict = self.text
            else:
                # Raw dict from one endpoint
                domain_dict = self.text

            # Determine apex domain for host assembly
            apex = None
            if isinstance(domain_dict, dict):
                apex = domain_dict.get('apex_domain') or domain_dict.get('hostname')
            if not apex:
                apex = base_domain

            # Parse IPs and subdomains
            if isinstance(domain_dict, dict):
                parse_domain_dict(domain_dict)
            if isinstance(subdomains_dict, dict):
                parse_subdomains_dict(subdomains_dict, apex)
            else:
                # If subdomains are embedded in the same dict
                parse_subdomains_dict(domain_dict if isinstance(domain_dict, dict) else {}, apex)

            return self.ips, self.hostnames

        # Fallback legacy string parsing
        text_lines = str(self.text).splitlines()
        sub_domain_flag = 0
        for index in range(0, len(text_lines)):
            line = text_lines[index].strip()
            if '"ip":' in line:
                ip = ''
                for ch in line[7:]:
                    if ch == '"':
                        break
                    else:
                        ip += ch
                ip = ip.strip().strip(',')
                add_ip(ip)
            elif '"ipv6":' in line:
                val = ''
                for ch in line[9:]:
                    if ch == '"':
                        break
                    else:
                        val += ch
                val = val.strip().strip(',')
                add_ip(val)
            elif '"subdomains":' in line:
                sub_domain_flag = 1
                continue
            elif sub_domain_flag > 0:
                if ']' in line:
                    sub_domain_flag = 0
                else:
                    self.hostnames.add(str(line).replace('"', '').replace(',', '') + '.' + base_domain)
        return self.ips, self.hostnames
