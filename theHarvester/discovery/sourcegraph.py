from __future__ import annotations

import json
import re
from typing import Any

from theHarvester.lib.core import AsyncFetcher, ResponseStreamError

_HOST_TOKEN = re.compile(
    r'(?<![\w*.-])(?:\*|[a-z0-9-]+)(?:\.(?:\*|[a-z0-9-]+))+\.?(?![\w*.-])',
    re.IGNORECASE,
)
_SPECIAL_USE_SUFFIXES = frozenset(
    {
        '6tisch.arpa',
        'alt',
        'eap-noob.arpa',
        'eap.arpa',
        'example',
        'example.com',
        'example.net',
        'example.org',
        'home.arpa',
        'in-addr.arpa',
        'internal',
        'invalid',
        'ip6.arpa',
        'ipv4only.arpa',
        'local',
        'localhost',
        'onion',
        'resolver.arpa',
        'service.arpa',
        'test',
    }
)


def _normalize_hostname(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    hostname = value.strip()
    if not hostname or not hostname.isascii() or hostname.endswith('..') or '*' in hostname:
        return None
    hostname = hostname.lower().removesuffix('.')
    labels = hostname.split('.')
    if len(hostname) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith('-')
        or label.endswith('-')
        or not all(character.isalnum() or character == '-' for character in label)
        for label in labels
    ):
        return None
    if len(labels) == 4 and all(label.isdigit() and len(label) <= 3 and int(label) <= 255 for label in labels):
        return None
    if any(hostname == suffix or hostname.endswith(f'.{suffix}') for suffix in _SPECIAL_USE_SUFFIXES):
        return None
    return hostname


def _parse_event(record: str) -> tuple[str, Any]:
    lines = record.splitlines()
    if len(lines) != 2 or not lines[0].startswith('event: ') or not lines[1].startswith('data: '):
        raise ValueError('invalid Sourcegraph event record')
    event_name = lines[0].removeprefix('event: ')
    if not event_name:
        raise ValueError('missing Sourcegraph event name')
    return event_name, json.loads(lines[1].removeprefix('data: '))


class SearchSourcegraph:
    """Collect descendant-hostname candidates mentioned in Sourcegraph code.

    One query to Sourcegraph requests up to 5,000 matches; ``--limit`` does not
    change it, and this source never contacts the target. A code mention does not
    prove ownership, scope, or liveness. Repository and shard limits, along with
    unstable result ordering, can make the results partial and non-exhaustive.
    """

    ENDPOINT = 'https://sourcegraph.com/.api/search/stream'
    MATCH_COUNT = 5000
    MAX_EVENTS = 10_000
    MAX_HOSTNAMES = 10_000
    MAX_LINE_LENGTH = 4096

    def __init__(self, word: str, limit: int) -> None:
        del limit  # Sourcegraph uses one fixed provider query; global --limit is unrelated.
        self.word = _normalize_hostname(word) or ''
        if '.' not in self.word:
            self.word = ''
        self.totalhosts: set[str] = set()
        self.proxy: bool | str = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None
        self._saw_done = False
        self._saw_terminal_progress = False
        self._final_progress_skipped = False

    def _stop(self, reason: str, status: str | None = None) -> None:
        self.execution_status = status or ('partial' if self.totalhosts else 'failed')
        self.stop_reason = reason

    def _add_content(self, content: str) -> None:
        for match in _HOST_TOKEN.finditer(content):
            hostname = _normalize_hostname(match.group())
            if hostname and hostname != self.word and hostname.endswith(f'.{self.word}'):
                if len(self.totalhosts) >= self.MAX_HOSTNAMES and hostname not in self.totalhosts:
                    raise OverflowError
                self.totalhosts.add(hostname)

    def _consume_matches(self, payload: object) -> None:
        if not isinstance(payload, list):
            raise ValueError('matches payload must be a list')
        for match in payload:
            if not isinstance(match, dict):
                raise ValueError('match must be an object')
            if match.get('type') != 'content':
                continue
            chunks = match.get('chunkMatches')
            if not isinstance(chunks, list):
                raise ValueError('content match must contain chunks')
            for chunk in chunks:
                if not isinstance(chunk, dict) or not isinstance(chunk.get('content'), str):
                    raise ValueError('chunk must contain text')
                self._add_content(chunk['content'])

    def _consume_event(self, record: str) -> str | None:
        if self._saw_done:
            raise ValueError('event after done')
        event_name, payload = _parse_event(record)
        if self._saw_terminal_progress and event_name != 'done':
            raise ValueError('event after terminal progress')
        if event_name == 'matches':
            self._consume_matches(payload)
        elif event_name == 'progress':
            if not isinstance(payload, dict):
                raise ValueError('progress payload must be an object')
            skipped = payload.get('skipped', [])
            if not isinstance(skipped, list):
                raise ValueError('progress skipped must be a list')
            done = payload.get('done')
            if not isinstance(done, bool):
                raise ValueError('progress done must be a boolean')
            if done:
                self._saw_terminal_progress = True
                self._final_progress_skipped = bool(skipped)
        elif event_name == 'done':
            if not isinstance(payload, dict):
                raise ValueError('done payload must be an object')
            self._saw_done = True
        elif event_name == 'error':
            return 'provider-error'
        elif event_name in {'filters', 'alert'}:
            pass
        else:
            raise ValueError('unknown Sourcegraph event')
        return None

    async def do_search(self) -> None:
        if not self.word:
            self._stop('invalid-target')
            return
        params = {
            'q': f'"{self.word}" type:file count:{self.MATCH_COUNT} timeout:10s patternType:keyword',
            'v': 'V3',
            'cm': 'true',
            'cl': 0,
            'max-line-len': self.MAX_LINE_LENGTH,
            'display': self.MATCH_COUNT,
        }
        try:
            async with AsyncFetcher.stream_records(
                self.ENDPOINT,
                framing='sse',
                headers={'Accept': 'text/event-stream'},
                params=params,
                proxy=self.proxy,
                follow_redirects=False,
                request_timeout=60,
            ) as response:
                if response.status == 429:
                    self._stop('http-429', 'rate-limited')
                    return
                if response.status in {401, 403}:
                    self._stop('access-denied')
                    return
                if not 200 <= response.status < 300:
                    self._stop(f'http-{response.status}')
                    return

                event_count = 0
                async for record in response:
                    event_count += 1
                    if event_count > self.MAX_EVENTS:
                        self._stop('response-limit')
                        return
                    try:
                        failure = self._consume_event(record)
                    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
                        self._stop('invalid-response')
                        return
                    except OverflowError:
                        self._stop('response-limit')
                        return
                    if failure:
                        self._stop(failure)
                        return
        except ResponseStreamError as error:
            self._stop(error.reason)
            return

        if not self._saw_done or not self._saw_terminal_progress:
            self._stop('invalid-response')
        elif self._final_progress_skipped:
            self._stop('provider-limited', 'partial')
        else:
            self.execution_status = 'completed'
            self.stop_reason = None if self.totalhosts else 'no-results'

    async def get_hostnames(self) -> list[str]:
        return sorted(self.totalhosts)

    async def process(self, proxy: bool | str = False) -> None:
        self.proxy = proxy
        await self.do_search()
