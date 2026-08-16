import logging

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse

logger = logging.getLogger(__name__)


class SearchLeakLookup:
    def __init__(self, word: str):
        self.word = word
        key = Core.leaklookup_key()
        self.api_key = key.strip() if key else ''
        if not self.api_key:
            raise MissingKey('Leak-Lookup')
        self.url = 'https://leak-lookup.com/api/search'
        self.hosts: set[str] = set()
        self.emails: set[str] = set()
        self.leaks: list[dict[str, str]] = []
        self.passwords: set[str] = set()
        self.sources: set[str] = set()
        self.leak_dates: set[str] = set()
        self.breach_names: set[str] = set()

    async def process(self, proxy: bool = False) -> None:
        response = await AsyncFetcher.post_fetch(
            self.url,
            headers={'User-Agent': Core.get_user_agent()},
            data={'key': self.api_key, 'type': 'domain', 'query': self.word},
            proxy=proxy,
            include_metadata=True,
        )
        if not isinstance(response, FetcherResponse):
            logger.info('Leak-Lookup request failed without a response')
            return
        if not 200 <= response.status < 300:
            logger.info(f'Leak-Lookup request failed with HTTP {response.status}')
            return
        if not isinstance(response.body, dict):
            logger.info('Leak-Lookup returned malformed data')
            return
        if response.body.get('error') in (True, 'true', 1, '1'):
            logger.info('Leak-Lookup request failed')
            return

        self._extract_data(response.body.get('message'))

    def _extract_data(self, message: object) -> None:
        if not isinstance(message, dict):
            logger.info('Leak-Lookup returned malformed data')
            return

        normalized_leaks: set[tuple[str, str | None]] = set()
        email_fields = ('email', 'email_address', 'emailaddress', 'email2', 'email_address2', 'emailaddress2')
        for breach, records in message.items():
            if not isinstance(breach, str) or not breach.strip():
                continue
            breach_name = breach.strip()
            self.breach_names.add(breach_name)
            self.sources.add(breach_name)
            breach_emails: set[str] = set()
            if isinstance(records, list):
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    breach_emails.update(
                        value.strip() for field in email_fields if isinstance((value := record.get(field)), str) and value.strip()
                    )
            self.emails.update(breach_emails)
            normalized_leaks.update((breach_name, email) for email in breach_emails)
            if not breach_emails:
                normalized_leaks.add((breach_name, None))

        self.leaks = [
            {'breach': breach, **({'email': email} if email else {})}
            for breach, email in sorted(normalized_leaks, key=lambda item: (item[0], item[1] or ''))
        ]

    async def get_hostnames(self) -> set[str]:
        return self.hosts

    async def get_emails(self) -> set[str]:
        return self.emails

    async def get_leaks(self) -> list[dict[str, str]]:
        return self.leaks

    async def get_passwords(self) -> set[str]:
        return self.passwords

    async def get_sources(self) -> set[str]:
        return self.sources

    async def get_leak_dates(self) -> set[str]:
        return self.leak_dates

    async def get_breach_names(self) -> set[str]:
        return self.breach_names
