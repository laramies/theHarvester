import json
import logging
from ipaddress import ip_address

import aiohttp

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchRobtex:
    """Gather IP addresses for a hostname from the Robtex passive DNS API."""

    def __init__(self, word) -> None:
        self.word = word
        self.totalips: set = set()
        self.proxy = False
        self.hostname = 'https://freeapi.robtex.com'

    @staticmethod
    def _safe_parse_json_lines(payload: str) -> list:
        """Parse JSONL (JSON Lines) format"""
        results: list = []
        if not payload:
            return results

        for line in payload.strip().split('\n'):
            if line.strip():
                try:
                    results.append(json.loads(line))
                except (TypeError, ValueError):
                    continue
        return results

    async def do_search(self) -> SourceExecutionReport | None:
        try:
            headers = {'User-agent': Core.get_user_agent()}

            url = f'{self.hostname}/pdns/forward/{self.word}'
            responses: list[FetcherResponse | None] = await AsyncFetcher.fetch_all(
                [url],
                headers=headers,
                proxy=self.proxy,
                include_metadata=True,
            )
            response = responses[0] if responses else None
            if response is None:
                logger.info(f'No response from Robtex API for: {url}')
                return SourceExecutionReport('failed', 'transport-error')
            if response.status == 429:
                logger.info('Robtex request was rate limited')
                return SourceExecutionReport('rate-limited', 'http-429')
            if not 200 <= response.status < 300:
                logger.info(f'Robtex request failed with HTTP {response.status}')
                return SourceExecutionReport('failed', f'http-{response.status}')
            if not isinstance(response.body, str):
                logger.info(f'No response from Robtex API for: {url}')
                return SourceExecutionReport('failed', 'invalid-response')
            if not response.body:
                return None

            try:
                data = self._safe_parse_json_lines(response.body)
            except (TypeError, ValueError) as e:
                logger.info(f'Failed to parse JSON lines from Robtex response: {e}')
                return SourceExecutionReport('failed', 'invalid-response')
            records = [
                record
                for record in data
                if isinstance(record, dict) and isinstance(record.get('rrtype'), str) and isinstance(record.get('rrdata'), str)
            ]
            if not records:
                logger.info('Robtex returned no valid DNS records')
                return SourceExecutionReport('failed', 'invalid-response')

            for record in records:
                rrdata = record['rrdata']
                rrtype = record['rrtype']

                if rrtype in {'A', 'AAAA'} and rrdata:
                    try:
                        self.totalips.add(str(ip_address(rrdata)))
                    except ValueError:
                        pass

        except (aiohttp.ClientError, TimeoutError, OSError) as e:
            logger.info(f'Robtex API error: {e}')
            return SourceExecutionReport('failed', 'transport-error')
        except (TypeError, ValueError) as e:
            logger.info(f'Robtex API error: {e}')
            return SourceExecutionReport('failed', 'invalid-response')
        return None

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
