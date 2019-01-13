class Parser:

    def __init__(self, word, text):
        self.word = word
        self.text = text
        self.hostnames = set()
        self.ips = set()

    def parse_text(self):
        sub_domain_flag = 0
        self.text = str(self.text).splitlines()
        # Split lines to get a list of lines.
        for index in range(0, len(self.text)):
            line = self.text[index].strip()
            if '"ip":' in line:
                # Extract IP.
                ip = ''
                for ch in line[7:]:
                    if ch == '"':
                        break
                    else:
                        ip += ch
                self.ips.add(ip)
            elif '"subdomains":' in line:
                # subdomains start here so set flag to 1
                sub_domain_flag = 1
                continue
            elif sub_domain_flag > 0:
                if ']' in line:
                    sub_domain_flag = 0
                else:
                    if 'www' in self.word:
                        self.word = str(self.word).replace('www.', '').replace('www', '')
                    # Remove www from word if entered
                    self.hostnames.add(str(line).replace('"', '').replace(',', '') + '.' + self.word)
            else:
                continue
        return list(self.ips), list(self.hostnames)
