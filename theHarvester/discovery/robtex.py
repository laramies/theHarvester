import json as _stdlib_json
import logging
from ipaddress import ip_address
from types import ModuleType

import aiohttp

from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse

logger = logging.getLogger(__name__)

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError as e:
    logger.info(f"'ujson' not available. Falling back to standard 'json' module. Reason: {e}")
except (AttributeError, OSError, RuntimeError, SystemError, ValueError) as e:
    logger.info(f"Unexpected error while importing 'ujson'. Falling back to standard 'json'. Reason: {e}")


class SearchRobtex:
    """Gather IP addresses for a hostname from the Robtex passive DNS API."""

    def __init__(self, word) -> None:
        self.word = word
        self.totalips: set = set()
        self.proxy = False
        self.hostname = 'https://freeapi.robtex.com'
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

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

    async def do_search(self) -> None:
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
                self.execution_status = 'failed'
                self.stop_reason = 'transport-error'
                logger.info(f'No response from Robtex API for: {url}')
                return
            if response.status == 429:
                self.execution_status = 'rate-limited'
                self.stop_reason = 'http-429'
                logger.info('Robtex request was rate limited')
                return
            if not 200 <= response.status < 300:
                self.execution_status = 'failed'
                self.stop_reason = f'http-{response.status}'
                logger.info(f'Robtex request failed with HTTP {response.status}')
                return
            if not isinstance(response.body, str):
                self.execution_status = 'failed'
                self.stop_reason = 'invalid-response'
                logger.info(f'No response from Robtex API for: {url}')
                return
            if not response.body:
                return

            try:
                data = self._safe_parse_json_lines(response.body)
            except (TypeError, ValueError) as e:
                logger.info(f'Failed to parse JSON lines from Robtex response: {e}')
                return
            records = [
                record
                for record in data
                if isinstance(record, dict) and isinstance(record.get('rrtype'), str) and isinstance(record.get('rrdata'), str)
            ]
            if not records:
                self.execution_status = 'failed'
                self.stop_reason = 'invalid-response'
                logger.info('Robtex returned no valid DNS records')
                return

            for record in records:
                rrdata = record['rrdata']
                rrtype = record['rrtype']

                if rrtype in {'A', 'AAAA'} and rrdata:
                    try:
                        self.totalips.add(str(ip_address(rrdata)))
                    except ValueError:
                        pass

        except (aiohttp.ClientError, TimeoutError, OSError) as e:
            self.execution_status = 'failed'
            self.stop_reason = 'transport-error'
            logger.info(f'Robtex API error: {e}')
        except (TypeError, ValueError) as e:
            self.execution_status = 'failed'
            self.stop_reason = 'invalid-response'
            logger.info(f'Robtex API error: {e}')

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        await self.do_search()
