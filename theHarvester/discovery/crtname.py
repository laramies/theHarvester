import asyncio

from theHarvester.lib.core import AsyncFetcher, ResponseStreamError
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchCrtName:
    """Collect hostname candidates for the exact operator-requested scope."""

    ENDPOINT = 'https://crt.name/v1/search'
    RUNTIME_SECONDS = 90

    def __init__(self, word: str) -> None:
        self.word = self._normalize_scope(word)
        self.hostnames: set[str] = set()
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    @staticmethod
    def _valid_hostname(value: str) -> bool:
        if not value or len(value) > 253 or not value.isascii():
            return False
        labels = value.split('.')
        return all(
            label
            and len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(character.isalnum() or character == '-' for character in label)
            for label in labels
        )

    @classmethod
    def _normalize_scope(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped.isascii():
            return ''
        normalized = stripped.lower().removesuffix('.')
        if normalized.endswith('.') or not cls._valid_hostname(normalized) or len(normalized.split('.')) < 2:
            return ''
        labels = normalized.split('.')
        if len(labels) == 4 and all(label.isdigit() and len(label) <= 3 and int(label) <= 255 for label in labels):
            return ''
        return normalized

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self.hostnames else status
        self.stop_reason = reason

    async def _collect(self, proxy: bool) -> None:
        async with AsyncFetcher.stream_records(
            self.ENDPOINT,
            framing='ndjson',
            params={'apex': self.word},
            headers={'Accept': 'text/plain'},
            proxy=proxy,
            follow_redirects=False,
            request_timeout=self.RUNTIME_SECONDS,
        ) as response:
            if response.status == 429:
                self._stop('rate-limited', 'http-429')
                return
            if response.status in {401, 403}:
                self._stop('failed', 'access-denied')
                return
            if not 200 <= response.status < 300:
                self._stop('failed', f'http-{response.status}')
                return

            malformed = False
            async for record in response:
                candidate = record.strip()
                if not candidate:
                    continue
                if not candidate.isascii():
                    malformed = True
                    continue
                candidate = candidate.lower().removeprefix('*.').removesuffix('.')
                if not self._valid_hostname(candidate):
                    malformed = True
                    continue
                normalized = normalize_scoped_hostname(candidate, self.word)
                if normalized is None:
                    malformed = True
                elif normalized != self.word:
                    self.hostnames.add(normalized)

            if malformed:
                self._stop('failed', 'invalid-response')
            else:
                self.execution_status = 'completed'
                self.stop_reason = None if self.hostnames else 'no-results'

    async def process(self, proxy: bool = False) -> None:
        self.execution_status = None
        self.stop_reason = None
        if not self.word:
            self._stop('failed', 'invalid-target')
            return
        try:
            async with asyncio.timeout(self.RUNTIME_SECONDS):
                await self._collect(proxy)
        except ResponseStreamError as error:
            self._stop('failed', error.reason)
        except TimeoutError:
            self._stop('failed', 'runtime-limit')

    async def get_hostnames(self) -> set[str]:
        return self.hostnames
