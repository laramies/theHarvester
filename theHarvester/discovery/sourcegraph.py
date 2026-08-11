import json

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.parsers import myparser


class SearchSourcegraph:
    """Gather scoped hostnames and emails from Sourcegraph's public code index."""

    MAX_RESULTS = 500

    def __init__(self, word: str, limit: int) -> None:
        self.word = word.lower().rstrip('.')
        self.limit = min(max(limit, 1), self.MAX_RESULTS)
        self.totalresults = ''
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    async def do_search(self) -> None:
        try:
            response = await AsyncFetcher.fetch(
                url='https://sourcegraph.com/.api/search/stream',
                headers={'Accept': 'text/event-stream', 'User-Agent': Core.get_user_agent()},
                params={
                    'q': f'"{self.word}" type:file count:{self.limit} timeout:10s patternType:keyword',
                    'v': 'V3',
                    'cm': 'false',
                },
                proxy=self.proxy,
                request_timeout=60,
                include_metadata=True,
            )
        except OSError:
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            return
        if not isinstance(response, FetcherResponse):
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            return
        if response.status == 429:
            self.execution_status = 'rate-limited'
            self.stop_reason = 'http-429'
            return
        if response.status in {401, 403}:
            self.execution_status = 'failed'
            self.stop_reason = 'access-denied'
            return
        if not 200 <= response.status < 300:
            self.execution_status = 'failed'
            self.stop_reason = f'http-{response.status}'
            return
        if not isinstance(response.body, str):
            self.execution_status = 'failed'
            self.stop_reason = 'invalid-response'
            return

        saw_done = False
        saw_error = False
        try:
            for block in response.body.replace('\r\n', '\n').split('\n\n'):
                if not block.strip():
                    continue
                if saw_done:
                    raise ValueError('event after done')
                event = next(line[6:].strip() for line in block.splitlines() if line.startswith('event:'))
                data = next(line[5:].strip() for line in block.splitlines() if line.startswith('data:'))
                payload = json.loads(data)
                if event == 'done':
                    if not isinstance(payload, dict):
                        raise ValueError('invalid done event')
                    saw_done = True
                elif event == 'matches':
                    if not isinstance(payload, list):
                        raise ValueError('invalid matches event')
                    for match in payload:
                        if not isinstance(match, dict):
                            raise ValueError('invalid match')
                        if match.get('type') != 'content':
                            continue
                        line_matches = match.get('lineMatches')
                        if not isinstance(line_matches, list):
                            raise ValueError('invalid content match')
                        for line_match in line_matches:
                            if not isinstance(line_match, dict) or not isinstance(line_match.get('line'), str):
                                raise ValueError('invalid line match')
                            self.totalresults += f' {line_match["line"]} '
                elif event == 'error':
                    if not isinstance(payload, dict) or not isinstance(payload.get('message'), str):
                        raise ValueError('invalid error event')
                    saw_error = True
                elif event in {'progress', 'alert'}:
                    if not isinstance(payload, dict):
                        raise ValueError(f'invalid {event} event')
                elif event == 'filters':
                    if not isinstance(payload, list):
                        raise ValueError('invalid filters event')
        except (StopIteration, ValueError):
            self.execution_status = 'partial' if self.totalresults else 'failed'
            self.stop_reason = 'invalid-response'
            return

        if not saw_done:
            self.execution_status = 'partial' if self.totalresults else 'failed'
            self.stop_reason = 'invalid-response'
            return
        if saw_error:
            self.execution_status = 'partial' if self.totalresults else 'failed'
            self.stop_reason = 'provider-error'
            return
        self.execution_status = 'completed'
        self.stop_reason = None if self.totalresults else 'no-results'

    async def get_emails(self) -> set[str]:
        return await myparser.Parser(self.totalresults, self.word).emails()

    async def get_hostnames(self) -> list[str]:
        return await myparser.Parser(self.totalresults, self.word).hostnames()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
