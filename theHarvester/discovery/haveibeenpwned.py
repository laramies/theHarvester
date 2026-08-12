import logging

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse

logger = logging.getLogger(__name__)


class SearchHaveIBeenPwned:
    def __init__(self, word: str):
        self.word = word
        self.base_url = 'https://haveibeenpwned.com/api/v3'
        self.headers = {'User-Agent': Core.get_user_agent(), 'Content-Type': 'application/json'}
        self.hosts: set[str] = set()
        self.emails: set[str] = set()
        self.breaches: list[dict] = []
        self.breach_names: set[str] = set()
        self.pastes: list[dict] = []
        self.breach_dates: set[str] = set()
        self.breach_types: set[str] = set()
        self.affected_data: set[str] = set()
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    async def process(self, proxy: bool = False) -> None:
        """Search for breaches associated with a domain or email."""
        self.execution_status = None
        self.stop_reason = None
        try:
            responses = await AsyncFetcher.fetch_all(
                [f'{self.base_url}/breaches?domain={self.word}'],
                headers=self.headers,
                json=True,
                proxy=proxy,
                include_metadata=True,
            )
        except (OSError, RuntimeError, ValueError):
            logger.info('HaveIBeenPwned request failed')
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            return

        response = responses[0] if responses and isinstance(responses[0], FetcherResponse) else None
        if response is None:
            logger.info('HaveIBeenPwned request failed')
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            return
        if response.status == 429:
            logger.info('HaveIBeenPwned request failed with HTTP 429')
            self.execution_status = 'rate-limited'
            self.stop_reason = 'http-429'
            return
        if not 200 <= response.status < 300:
            logger.info(f'HaveIBeenPwned request failed with HTTP {response.status}')
            self.execution_status = 'failed'
            self.stop_reason = f'http-{response.status}'
            return
        if not isinstance(response.body, list) or not all(isinstance(breach, dict) for breach in response.body):
            logger.info('HaveIBeenPwned returned malformed breach data')
            self.execution_status = 'failed'
            self.stop_reason = 'invalid-response'
            return

        self.breaches = response.body
        self._extract_data()
        self.execution_status = 'completed'
        self.stop_reason = None if self.breaches else 'no-results'

    def _extract_data(self) -> None:
        """Extract and categorize breach information."""
        for breach in self.breaches:
            if isinstance(name := breach.get('Name'), str) and name.strip():
                self.breach_names.add(name.strip())
            if isinstance(domain := breach.get('Domain'), str):
                self.hosts.add(domain)
            if isinstance(breach_date := breach.get('BreachDate'), str):
                self.breach_dates.add(breach_date)
            if isinstance(breach_type := breach.get('BreachType'), str):
                self.breach_types.add(breach_type)
            if isinstance(data_classes := breach.get('DataClasses'), list):
                self.affected_data.update(item for item in data_classes if isinstance(item, str))

    async def get_hostnames(self) -> set[str]:
        return self.hosts

    async def get_emails(self) -> set[str]:
        return self.emails

    async def get_breaches(self) -> list[dict]:
        return self.breaches

    async def get_breach_names(self) -> set[str]:
        return self.breach_names

    async def get_pastes(self) -> list[dict]:
        return self.pastes

    async def get_breach_dates(self) -> set[str]:
        return self.breach_dates

    async def get_breach_types(self) -> set[str]:
        return self.breach_types

    async def get_affected_data(self) -> set[str]:
        return self.affected_data
