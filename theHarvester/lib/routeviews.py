from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote

from theHarvester.lib.core import AsyncFetcher, FetcherResponse, ResponseStreamError
from theHarvester.lib.network_evidence import (
    MAX_NETWORK_DETAILS_BYTES,
    MAX_NETWORK_OBSERVATIONS_PER_PREFIX,
    BgpRouteObservation,
    NetworkEvidenceAccumulator,
    NetworkEvidenceLimitError,
    PrefixOriginObservation,
    RpkiValidationObservation,
)
from theHarvester.lib.result_values import normalize_asn, normalize_prefix

if TYPE_CHECKING:
    from collections.abc import Iterable

    from theHarvester.lib.evidence_types import ExecutionStatus
    from theHarvester.lib.network_evidence import NetworkObservation, RpkiState

ROUTEVIEWS_BASE = 'https://api.routeviews.org'
ROUTEVIEWS_GUEST_BASE = f'{ROUTEVIEWS_BASE}/guest'
MAX_ROUTEVIEWS_REQUESTS = 300
MAX_ROUTEVIEWS_RUNTIME_SECONDS = 300.0
MAX_ROUTEVIEWS_INPUT_ITEMS = 1_000
MAX_ROUTEVIEWS_RUN_ITEMS = 100_000
MAX_ROUTEVIEWS_RUN_JSON_BYTES = 32 * 1024 * 1024
ROUTEVIEWS_GUEST_INTERVAL_SECONDS = 1.0
ROUTEVIEWS_AUTHENTICATED_INTERVAL_SECONDS = 0.1
ROUTEVIEWS_REQUEST_TIMEOUT_SECONDS = 30


async def _fetch_json(url: str, **kwargs: Any) -> FetcherResponse:
    return await AsyncFetcher.fetch_json(url, **kwargs)


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def _monotonic() -> float:
    return time.monotonic()


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class RouteViewsResult:
    prefixes: tuple[str, ...]
    origin_asns: tuple[str, ...]
    observations: tuple[NetworkObservation, ...]
    request_count: int
    error_count: int
    status: ExecutionStatus
    error_type: str | None = None
    stop_reason: str | None = None


class RouteViewsCancelled(asyncio.CancelledError):
    def __init__(self, result: RouteViewsResult) -> None:
        self.result = result
        super().__init__('RouteViews enrichment cancelled')


class _RouteViewsStopError(Exception):
    def __init__(self, error_type: str, stop_reason: str, *, terminal: bool = True) -> None:
        self.error_type = error_type
        self.stop_reason = stop_reason
        self.terminal = terminal
        super().__init__(stop_reason)


def _canonical_asns(values: Iterable[str | int]) -> tuple[tuple[str, ...], bool]:
    normalized: set[str] = set()
    if isinstance(values, (str, bytes)):
        return (), False
    truncated = False
    for index, value in enumerate(values):
        if index >= MAX_ROUTEVIEWS_INPUT_ITEMS:
            truncated = True
            break
        if isinstance(value, str) and len(value) > 32:
            continue
        try:
            normalized.add(normalize_asn(value))
        except TypeError, ValueError:
            continue
    return tuple(sorted(normalized, key=lambda value: int(value[2:]))), truncated


def _canonical_network_seeds(values: Iterable[str]) -> tuple[tuple[str, ...], bool]:
    normalized: set[str] = set()
    if isinstance(values, (str, bytes)):
        return (), False
    truncated = False
    for index, value in enumerate(values):
        if index >= MAX_ROUTEVIEWS_INPUT_ITEMS:
            truncated = True
            break
        if not isinstance(value, str) or len(value) > 128 or '%' in value:
            continue
        try:
            normalized.add(normalize_prefix(value) if '/' in value else str(ip_address(value.strip())))
        except ValueError:
            continue

    def sort_key(value: str) -> tuple[int, int, int]:
        network = ip_network(value, strict=False) if '/' in value else ip_network(value)
        return network.version, int(network.network_address), network.prefixlen

    return tuple(sorted(normalized, key=sort_key)), truncated


def _provider_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError('RouteViews timestamp must be a string')
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError('RouteViews timestamp must be timezone-aware')
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as error:
        raise ValueError('RouteViews timestamp is invalid') from error


def _rpki_state(value: object) -> RpkiState:
    if value == 'notfound':
        return 'not-found'
    if value in {'valid', 'invalid', 'not-found'}:
        return cast('RpkiState', value)
    raise ValueError('RouteViews RPKI state is invalid')


class _RouteViewsRuntime:
    def __init__(self, api_key: str | None = None, *, proxy: bool = False) -> None:
        self.base_url = ROUTEVIEWS_BASE if api_key else ROUTEVIEWS_GUEST_BASE
        self.headers = {'Api-Key': api_key} if api_key else None
        self.proxy = proxy
        self.request_interval = ROUTEVIEWS_AUTHENTICATED_INTERVAL_SECONDS if api_key else ROUTEVIEWS_GUEST_INTERVAL_SECONDS
        self.started_at = _monotonic()
        self.last_request_at: float | None = None
        self.request_count = 0
        self.error_count = 0
        self.reported_error_type: str | None = None
        self.reported_stop_reason: str | None = None
        self.run_item_count = 0
        self.run_json_bytes = 0
        self.prefixes: set[str] = set()
        self.origin_asns: set[str] = set()
        self.evidence = NetworkEvidenceAccumulator(
            max_observations_per_prefix=MAX_NETWORK_OBSERVATIONS_PER_PREFIX,
            max_details_bytes=MAX_NETWORK_DETAILS_BYTES,
        )

    def _record_error(self, error_type: str, stop_reason: str, *, override: bool = False) -> None:
        self.error_count += 1
        if self.reported_error_type is None or override:
            self.reported_error_type = error_type
            self.reported_stop_reason = stop_reason

    def _charge_items(self, count: int) -> None:
        self.run_item_count += count
        if self.run_item_count > MAX_ROUTEVIEWS_RUN_ITEMS:
            raise _RouteViewsStopError('RouteViewsLimitError', 'result-limit')

    def _accept_observation(self, observation: NetworkObservation) -> bool:
        try:
            return self.evidence.add(observation)
        except NetworkEvidenceLimitError as error:
            raise _RouteViewsStopError('RouteViewsLimitError', 'result-limit') from error

    def _add_origin(self, prefix: object, origin_asn: object, collected_at: datetime) -> tuple[str, str]:
        if not isinstance(prefix, str) or isinstance(origin_asn, bool) or not isinstance(origin_asn, (str, int)):
            raise ValueError('RouteViews origin must contain a prefix and ASN')
        normalized_prefix = normalize_prefix(prefix)
        normalized_asn = normalize_asn(origin_asn)
        key = normalized_prefix, normalized_asn
        self._accept_observation(
            PrefixOriginObservation(
                action='routeviews',
                prefix=normalized_prefix,
                origin_asn=normalized_asn,
                collected_at=collected_at,
            )
        )
        self.prefixes.add(normalized_prefix)
        self.origin_asns.add(normalized_asn)
        return key

    def _add_route(
        self,
        *,
        prefix: object,
        origin_asn: object,
        peer: object,
        collected_at: datetime,
    ) -> None:
        if not isinstance(peer, dict):
            raise ValueError('RouteViews reporting peer must be an object')
        collector = peer.get('collector')
        peer_asn = peer.get('peer_asn')
        peer_address = peer.get('peer_addr')
        as_path = peer.get('as_path')
        communities = peer.get('communities')
        if (
            not isinstance(collector, str)
            or isinstance(peer_asn, bool)
            or not isinstance(peer_asn, (str, int))
            or not isinstance(peer_address, str)
            or not isinstance(as_path, str)
            or not isinstance(communities, str)
        ):
            raise ValueError('RouteViews reporting peer has invalid fields')
        normalized_prefix, normalized_asn = self._add_origin(prefix, origin_asn, collected_at)
        route = BgpRouteObservation(
            action='routeviews',
            prefix=normalized_prefix,
            origin_asn=normalized_asn,
            collector=collector,
            peer_asn=peer_asn,
            peer_address=peer_address,
            as_path=as_path,
            communities=communities,
            observed_at=_provider_time(peer.get('timestamp')),
            collected_at=collected_at,
        )
        self._accept_observation(route)

    def _add_rpki(
        self,
        *,
        prefix: object,
        origin_asn: object,
        state: object,
        observed_at: datetime,
        collected_at: datetime,
    ) -> None:
        normalized_prefix, normalized_asn = self._add_origin(prefix, origin_asn, collected_at)
        observation = RpkiValidationObservation(
            action='routeviews',
            prefix=normalized_prefix,
            origin_asn=normalized_asn,
            state=_rpki_state(state),
            observed_at=observed_at,
            collected_at=collected_at,
        )
        self._accept_observation(observation)

    async def _request(self, url: str, *, params: object = '') -> FetcherResponse:
        if self.request_count >= MAX_ROUTEVIEWS_REQUESTS:
            raise _RouteViewsStopError('RouteViewsLimitError', 'request-limit')
        elapsed = _monotonic() - self.started_at
        if elapsed >= MAX_ROUTEVIEWS_RUNTIME_SECONDS:
            raise _RouteViewsStopError('RouteViewsLimitError', 'runtime-limit')
        if self.last_request_at is not None:
            delay = self.request_interval - (_monotonic() - self.last_request_at)
            if delay > 0:
                if elapsed + delay >= MAX_ROUTEVIEWS_RUNTIME_SECONDS:
                    raise _RouteViewsStopError('RouteViewsLimitError', 'runtime-limit')
                await _sleep(delay)
        remaining = MAX_ROUTEVIEWS_RUNTIME_SECONDS - (_monotonic() - self.started_at)
        if remaining <= 0:
            raise _RouteViewsStopError('RouteViewsLimitError', 'runtime-limit')
        self.request_count += 1
        self.last_request_at = _monotonic()
        request_kwargs: dict[str, Any] = {
            'params': params,
            'request_timeout': min(ROUTEVIEWS_REQUEST_TIMEOUT_SECONDS, max(1, math.ceil(remaining))),
        }
        if self.headers is not None:
            request_kwargs['headers'] = self.headers
        if self.proxy:
            request_kwargs['proxy'] = True
        try:
            async with asyncio.timeout(remaining):
                response = await _fetch_json(url, **request_kwargs)
        except ResponseStreamError as error:
            raise _RouteViewsStopError(
                type(error).__name__,
                error.reason,
                terminal=error.reason == 'response-limit',
            ) from error
        except TimeoutError as error:
            raise _RouteViewsStopError('RouteViewsLimitError', 'runtime-limit') from error
        if response.status == 429:
            raise _RouteViewsStopError('HTTPStatusError', 'http-429')
        if not 200 <= response.status < 300:
            raise _RouteViewsStopError(
                'HTTPStatusError',
                f'http-{response.status}',
                terminal=response.status in {401, 403},
            )
        if response.body is None:
            raise _RouteViewsStopError('ValueError', 'invalid-response', terminal=False)
        try:
            encoded_size = len(
                json.dumps(response.body, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
            )
        except (RecursionError, TypeError, ValueError, UnicodeEncodeError) as error:
            raise _RouteViewsStopError('ValueError', 'invalid-response', terminal=False) from error
        self.run_json_bytes += encoded_size
        if self.run_json_bytes > MAX_ROUTEVIEWS_RUN_JSON_BYTES:
            raise _RouteViewsStopError('RouteViewsLimitError', 'result-limit')
        return response

    def _require_items(self, value: object, label: str) -> list[object]:
        if not isinstance(value, list):
            raise ValueError(f'RouteViews {label} must be an array')
        self._charge_items(len(value))
        return value

    def _parse_asn(self, body: object, origin_asn: str, collected_at: datetime) -> None:
        for prefix in self._require_items(body, 'ASN response'):
            try:
                self._add_origin(prefix, origin_asn, collected_at)
            except ValueError:
                self._record_error('ValueError', 'invalid-response')

    def _parse_rpki(self, body: object, origin_asn: str, collected_at: datetime) -> None:
        if not isinstance(body, dict):
            raise ValueError('RouteViews RPKI response must be an object')
        record = body.get(origin_asn[2:])
        if record is None:
            return
        if not isinstance(record, dict):
            raise ValueError('RouteViews RPKI ASN record must be an object or null')
        observed_at = _provider_time(record.get('timestamp'))
        for item in self._require_items(record.get('prefix'), 'RPKI prefix list'):
            try:
                if not isinstance(item, dict) or len(item) != 1:
                    raise ValueError('RouteViews RPKI prefix entry must contain one prefix and state')
                prefix, state = next(iter(item.items()))
                self._add_rpki(
                    prefix=prefix,
                    origin_asn=origin_asn,
                    state=state,
                    observed_at=observed_at,
                    collected_at=collected_at,
                )
            except ValueError:
                self._record_error('ValueError', 'invalid-response')

    def _parse_prefix(self, body: object, seed: str, collected_at: datetime) -> None:
        requested_network = ip_network(seed, strict=False) if '/' in seed else None
        requested_address = ip_address(seed) if requested_network is None else None
        matching_groups: list[dict[object, object]] = []
        longest_prefix_length = -1
        for group in self._require_items(body, 'prefix response'):
            try:
                if not isinstance(group, dict):
                    raise ValueError('RouteViews prefix group must be an object')
                prefix = group.get('prefix')
                if not isinstance(prefix, str):
                    raise ValueError('RouteViews prefix group must contain a prefix')
                returned_network = ip_network(normalize_prefix(prefix))
                if (requested_network is not None and returned_network != requested_network) or (
                    requested_address is not None and requested_address not in returned_network
                ):
                    raise ValueError('RouteViews prefix response is unrelated to its seed')
                if requested_address is not None:
                    if returned_network.prefixlen > longest_prefix_length:
                        matching_groups.clear()
                        longest_prefix_length = returned_network.prefixlen
                    elif returned_network.prefixlen < longest_prefix_length:
                        continue
                matching_groups.append(group)
            except ValueError:
                self._record_error('ValueError', 'invalid-response')

        for group in matching_groups:
            prefix = group['prefix']
            try:
                origin_asn = group.get('origin_asn')
                self._add_origin(prefix, origin_asn, collected_at)
            except ValueError:
                self._record_error('ValueError', 'invalid-response')
                continue
            try:
                self._add_rpki(
                    prefix=prefix,
                    origin_asn=origin_asn,
                    state=group.get('rpki_state'),
                    observed_at=collected_at,
                    collected_at=collected_at,
                )
            except ValueError:
                self._record_error('ValueError', 'invalid-response')
            try:
                peers = self._require_items(group.get('reporting_peers'), 'reporting peers')
            except ValueError:
                self._record_error('ValueError', 'invalid-response')
                continue
            for peer in peers:
                try:
                    self._add_route(prefix=prefix, origin_asn=origin_asn, peer=peer, collected_at=collected_at)
                except ValueError:
                    self._record_error('ValueError', 'invalid-response')

    def _result(self) -> RouteViewsResult:
        observations = self.evidence.observations()
        if self.error_count == 0:
            status: ExecutionStatus = 'completed'
            stop_reason = None if self.prefixes else 'no-results'
        elif self.prefixes:
            status = 'partial'
            stop_reason = self.reported_stop_reason
        elif self.reported_stop_reason == 'http-429':
            status = 'rate-limited'
            stop_reason = self.reported_stop_reason
        else:
            status = 'failed'
            stop_reason = self.reported_stop_reason
        return RouteViewsResult(
            prefixes=tuple(sorted(self.prefixes)),
            origin_asns=tuple(sorted(self.origin_asns, key=lambda value: int(value[2:]))),
            observations=observations,
            request_count=self.request_count,
            error_count=self.error_count,
            status=status,
            error_type=self.reported_error_type,
            stop_reason=stop_reason,
        )

    async def run(self, asns: Iterable[str | int], network_seeds: Iterable[str]) -> RouteViewsResult:
        canonical_asns, asns_truncated = _canonical_asns(asns)
        canonical_seeds, seeds_truncated = _canonical_network_seeds(network_seeds)
        if asns_truncated or seeds_truncated:
            self._record_error('RouteViewsLimitError', 'input-limit')
        if not canonical_asns and not canonical_seeds:
            if self.error_count:
                return self._result()
            return RouteViewsResult((), (), (), 0, 0, 'skipped', stop_reason='no-input')

        async def collect(url: str, parser: Any, *, params: object = '') -> None:
            try:
                response = await self._request(url, params=params)
                parser(response.body, _now())
            except _RouteViewsStopError as error:
                self._record_error(error.error_type, error.stop_reason, override=error.terminal)
                if error.terminal:
                    raise
            except TypeError, ValueError:
                self._record_error('ValueError', 'invalid-response')

        try:
            for origin_asn in canonical_asns:
                await collect(
                    f'{self.base_url}/asn/{origin_asn[2:]}',
                    lambda body, collected_at, asn=origin_asn: self._parse_asn(body, asn, collected_at),
                )
                await collect(
                    f'{self.base_url}/rpki',
                    lambda body, collected_at, asn=origin_asn: self._parse_rpki(body, asn, collected_at),
                    params={'asn': origin_asn[2:]},
                )
            for seed in canonical_seeds:
                query_seed = seed if '/' in seed else str(ip_network(seed, strict=False))
                await collect(
                    f'{self.base_url}/prefix/{quote(query_seed, safe="")}',
                    lambda body, collected_at, requested_seed=seed: self._parse_prefix(body, requested_seed, collected_at),
                    params={'strict-match': 'yes'} if '/' in seed else '',
                )
        except _RouteViewsStopError:
            return self._result()
        except asyncio.CancelledError:
            self._record_error('CancelledError', 'cancelled', override=True)
            raise RouteViewsCancelled(self._result()) from None
        return self._result()


async def enrich_routeviews(
    asns: Iterable[str | int],
    network_seeds: Iterable[str],
    *,
    api_key: str | None = None,
    proxy: bool = False,
) -> RouteViewsResult:
    """Collect bounded routing evidence for caller-approved network pivots.

    Domain runs automatically pass harvested IPs that have sourced IP-to-ASN
    attribution. Bare ASN findings are not expanded into complete prefix
    inventories; that requires an explicit ASN target.
    """
    return await _RouteViewsRuntime(api_key, proxy=proxy).run(asns, network_seeds)
