import time

import requests

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core


class SearchDehashed:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.dehashed_key()
        if self.key is None:
            raise MissingKey('Dehashed')

        self.api = 'https://api.dehashed.com/v2/search'
        self.headers = {'Content-Type': 'application/json', 'Dehashed-Api-Key': self.key}
        self.results = ''
        self.data: list[dict] = []

    async def do_search(self) -> None:
        print(f'\t[+] Performing Dehashed search for: {self.word}')
        page = 1
        size = 100
        while True:
            payload = {'query': self.word, 'page': page, 'size': size, 'wildcard': False, 'regex': False, 'de_dupe': False}

            try:
                response = requests.post(self.api, json=payload, headers=self.headers)
                if response.status_code == 401:
                    raise Exception('Unauthorized. Check Dehashed API key.')
                if response.status_code == 403:
                    raise Exception('Forbidden. API key is not allowed.')

                data = response.json()
                entries = data.get('entries', [])
                if not entries:
                    break

                self.data.extend(entries)
                print(f'\t[+] Page {page} - Retrieved {len(entries)} entries.')

                if len(entries) < size:
                    break
                page += 1
                time.sleep(0.5)
            except Exception as e:
                print(f'\t[!] Dehashed error: {e}')
                break

    async def print_csv_results(self) -> None:
        if not self.data:
            print('\t[!] No data found.')
            return

        print('\n[Dehashed Results]')
        print('Email,Username,Password,Phone,IP,Source')

        for entry in self.data:
            email = entry.get('email', '')
            username = entry.get('username', '')
            password = entry.get('password', '')
            phone = entry.get('phone', '')
            ip = entry.get('ip_address', '')
            source = entry.get('database_name', '')

            csv_line = f'"{email}","{username}","{password}","{phone}","{ip}","{source}"'
            print(csv_line)

    async def process(self, proxy: bool = False) -> None:
        await self.do_search()
        await self.print_csv_results()

    async def get_emails(self) -> set:
        emails = set()
        for entry in self.data:
            if entry.get('email'):
                emails.add(entry['email'])
        return emails

    async def get_hostnames(self) -> set:
        return set()

    async def get_ips(self) -> set:
        ips = set()
        for entry in self.data:
            if entry.get('ip_address'):
                ips.add(entry['ip_address'])
        return ips
