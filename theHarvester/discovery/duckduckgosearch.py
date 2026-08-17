from typing import Any

from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, ResponseStreamError
from theHarvester.lib.source_execution import SourceExecutionReport
from theHarvester.parsers import myparser

_TEXT_FIELDS = (
    'Abstract',
    'AbstractSource',
    'AbstractText',
    'AbstractURL',
    'Answer',
    'AnswerType',
    'Definition',
    'DefinitionSource',
    'DefinitionURL',
    'Entity',
    'Heading',
    'Image',
    'Redirect',
    'Type',
)
_TOPIC_TEXT_FIELDS = ('FirstURL', 'Name', 'Result', 'Text')


def _topic_text(items: object) -> list[str] | None:
    if not isinstance(items, list):
        return None
    text: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            return None
        recognized = False
        for field in _TOPIC_TEXT_FIELDS:
            if field not in item:
                continue
            recognized = True
            value = item[field]
            if not isinstance(value, str):
                return None
            text.append(value)
        if 'Topics' in item:
            recognized = True
            nested = _topic_text(item['Topics'])
            if nested is None:
                return None
            text.extend(nested)
        if item and not recognized:
            return None
    return text


def _provider_text(body: dict[str, Any]) -> str | None:
    if not body:
        return ''
    recognized = False
    text: list[str] = []
    for field in _TEXT_FIELDS:
        if field not in body:
            continue
        recognized = True
        value = body[field]
        if not isinstance(value, str):
            return None
        text.append(value)
    for field in ('RelatedTopics', 'Results'):
        if field not in body:
            continue
        recognized = True
        topic_text = _topic_text(body[field])
        if topic_text is None:
            return None
        text.extend(topic_text)
    if not recognized:
        return None
    return '\n'.join(text)


class SearchDuckDuckGo:
    def __init__(self, word, limit) -> None:
        self.word = word
        self.results = ''
        self.totalresults = ''
        self.dorks: list[str] = []
        self.links: list[str] = []
        self.database = 'https://duckduckgo.com/?q='
        self.api = 'https://api.duckduckgo.com/?q=x&format=json&pretty=1'  # Currently using API.
        self.quantity = '100'
        self.limit = limit
        self.proxy: bool = False

    async def do_search(self) -> SourceExecutionReport | None:
        # Query only the provider; URLs in the response are evidence, not crawl targets.
        url = self.api.replace('x', self.word)
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            response = await AsyncFetcher.fetch_json(url, headers=headers, proxy=self.proxy)
        except ResponseStreamError as error:
            return SourceExecutionReport('failed', error.reason)
        if failure := provider_http_error(response):
            return SourceExecutionReport(*failure)
        if not isinstance(response.body, dict):
            return SourceExecutionReport('failed', 'invalid-response')
        if 'error' in response.body:
            provider_error = str(response.body['error']).lower()
            if 'rate limit' in provider_error:
                return SourceExecutionReport('rate-limited', 'provider-rate-limit')
            if 'access denied' in provider_error or 'forbidden' in provider_error:
                return SourceExecutionReport('failed', 'access-denied')
            return SourceExecutionReport('failed', 'provider-error')
        provider_text = _provider_text(response.body)
        if provider_text is None:
            return SourceExecutionReport('failed', 'invalid-response')
        self.results = provider_text
        self.totalresults += self.results
        return None

    async def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()  # Only need to search once since using API.
