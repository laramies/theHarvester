from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
from typing import TYPE_CHECKING

import aiodns
import aiohttp

from theHarvester.lib.cancellation import drain_tasks_after_cancellation
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.hostnames import normalize_hostname, normalize_scoped_hostname
from theHarvester.lib.output import output_logger
from theHarvester.lib.takeover_evidence import (
    HttpScheme,
    TakeoverCandidateOutcome,
    TakeoverCandidateStatus,
    TakeoverDNSOutcome,
    TakeoverHTTPOutcome,
    TakeoverIndicator,
    TakeoverRcode,
    canonical_takeover_outcomes,
)
from theHarvester.lib.takeover_rules import (
    TAKEOVER_RULE_REVISION,
    TAKEOVER_RULES,
    TakeoverRule,
    validate_takeover_rules,
)

DEFAULT_TAKEOVER_CONCURRENCY = 20
MAX_TAKEOVER_RESPONSE_BYTES = 1024 * 1024
MAX_CNAME_HOPS = 32

if TYPE_CHECKING:
    from collections.abc import Iterable


class TakeoverDNSResolver:
    """Resolve complete external CNAME relationships through one configured vantage."""

    def __init__(self, nameserver: str) -> None:
        self.nameserver = str(ipaddress.ip_address(nameserver))
        self._resolver = aiodns.DNSResolver(nameservers=[self.nameserver])

    async def query(self, hostname: str) -> TakeoverDNSOutcome:
        current = hostname
        chain: list[str] = []
        seen = {current}
        for _hop in range(MAX_CNAME_HOPS):
            results = await asyncio.gather(
                *(self._resolver.query_dns(current, record_type) for record_type in ('A', 'AAAA', 'CNAME')),
                return_exceptions=True,
            )
            next_cnames: list[str] = []
            dns_errors: list[int] = []
            error_types: set[str] = set()
            address_found = False
            for record_type, result in zip(('A', 'AAAA', 'CNAME'), results, strict=True):
                if isinstance(result, asyncio.CancelledError):
                    raise result
                if isinstance(result, Exception):
                    if isinstance(result, aiodns.error.DNSError) and result.args:
                        error_code = int(result.args[0])
                        dns_errors.append(error_code)
                        if error_code not in {aiodns.error.ARES_ENOTFOUND, aiodns.error.ARES_ENODATA}:
                            error_types.add(type(result).__name__)
                    else:
                        error_types.add(type(result).__name__)
                    continue
                if isinstance(result, BaseException):
                    raise result
                for record in result.answer:
                    if record_type == 'CNAME':
                        value = getattr(record.data, 'cname', None)
                        if isinstance(value, str):
                            try:
                                next_cnames.append(normalize_hostname(value))
                            except ValueError:
                                error_types.add('InvalidCNAMEError')
                        continue
                    value = getattr(record.data, 'addr', None)
                    if isinstance(value, str):
                        try:
                            ipaddress.ip_address(value)
                        except ValueError:
                            error_types.add('InvalidAddressError')
                        else:
                            address_found = True
            next_cnames = list(dict.fromkeys(next_cnames))
            if next_cnames:
                for cname in next_cnames:
                    if cname not in chain:
                        chain.append(cname)
                current = next_cnames[-1]
                if current in seen:
                    return TakeoverDNSOutcome(
                        resolver=self.nameserver,
                        cname_chain=tuple(chain),
                        terminal_rcode='ERROR',
                        error_type='CNAMECycleError',
                    )
                seen.add(current)
                continue
            terminal_rcode: TakeoverRcode
            if address_found:
                terminal_rcode = 'NOERROR'
            elif dns_errors and all(code == aiodns.error.ARES_ENOTFOUND for code in dns_errors):
                terminal_rcode = 'NXDOMAIN'
            elif dns_errors and all(code in {aiodns.error.ARES_ENOTFOUND, aiodns.error.ARES_ENODATA} for code in dns_errors):
                terminal_rcode = 'NODATA'
            else:
                terminal_rcode = 'ERROR'
            error_type = next(iter(sorted(error_types)), None)
            if terminal_rcode == 'ERROR' and error_type is None:
                error_type = 'DNSError'
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=tuple(chain),
                terminal_rcode=terminal_rcode,
                error_type=error_type,
            )
        return TakeoverDNSOutcome(
            resolver=self.nameserver,
            cname_chain=tuple(chain),
            terminal_rcode='ERROR',
            error_type='CNAMEHopLimitError',
        )

    async def close(self) -> None:
        await self._resolver.close()


def _candidate_hostname(value: object, target: str) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if candidate.count(':') == 1:
        hostname, address = candidate.split(':', 1)
        try:
            ipaddress.ip_address(address)
        except ValueError:
            pass
        else:
            candidate = hostname
    scoped = normalize_scoped_hostname(candidate, target)
    if scoped is None:
        return None
    try:
        return normalize_hostname(scoped)
    except ValueError:
        return None


def _rule_matches_dns(rule: TakeoverRule, outcome: TakeoverDNSOutcome) -> bool:
    return any(re.search(pattern, cname, flags=re.IGNORECASE) for pattern in rule.cname_patterns for cname in outcome.cname_chain)


def _wildcard_probe_hostname(hostname: str, target: str) -> str:
    suffix = hostname.partition('.')[2] if hostname != target else target
    if suffix != target and not suffix.endswith(f'.{target}'):
        raise ValueError('takeover wildcard control must remain inside the authorized target')
    return f'takeover-control-{secrets.token_hex(12)}.{suffix}'


def _dns_outcomes_disagree(outcomes: tuple[TakeoverDNSOutcome, ...]) -> bool:
    return len({(outcome.cname_chain, outcome.terminal_rcode) for outcome in outcomes}) > 1


def _dns_outcome_errors(outcomes: tuple[TakeoverDNSOutcome, ...]) -> set[str]:
    return {
        outcome.error_type or 'DNSError'
        for outcome in outcomes
        if outcome.error_type is not None or outcome.terminal_rcode == 'ERROR'
    }


def _rule_has_resolver_disagreement(rule: TakeoverRule, outcomes: tuple[TakeoverDNSOutcome, ...]) -> bool:
    matches = [_rule_matches_dns(rule, outcome) for outcome in outcomes]
    return any(matches) and not all(matches)


def _wildcard_rule_state(
    rule: TakeoverRule,
    candidates: tuple[TakeoverDNSOutcome, ...],
    controls: tuple[TakeoverDNSOutcome, ...],
) -> str:
    candidate_by_resolver = {outcome.resolver: outcome for outcome in candidates}
    control_by_resolver = {outcome.resolver: outcome for outcome in controls}
    equivalent: list[bool] = []
    for resolver, candidate in candidate_by_resolver.items():
        control = control_by_resolver.get(resolver)
        equivalent.append(
            control is not None
            and _rule_matches_dns(rule, candidate)
            and _rule_matches_dns(rule, control)
            and candidate.cname_chain == control.cname_chain
            and candidate.terminal_rcode == control.terminal_rcode
        )
    if equivalent and all(equivalent):
        return 'indistinguishable'
    if any(equivalent):
        return 'disagreement'
    return 'distinct'


def _match_http(rule: TakeoverRule, response: FetcherResponse) -> tuple[str, ...]:
    body = str(response.body)
    headers = '\n'.join(f'{name}: {value}' for name, value in sorted(response.headers.items()))
    body_folded = body.casefold()
    headers_folded = headers.casefold()
    if rule.status_codes and response.status not in rule.status_codes:
        return ()
    if any(pattern.casefold() not in body_folded for pattern in rule.body_all):
        return ()
    if rule.body_any and not any(pattern.casefold() in body_folded for pattern in rule.body_any):
        return ()
    if any(pattern.casefold() in body_folded for pattern in rule.body_none):
        return ()
    if any(re.search(pattern, body, flags=re.IGNORECASE) is None for pattern in rule.body_regex_all):
        return ()
    if rule.body_regex_any and not any(re.search(pattern, body, flags=re.IGNORECASE) for pattern in rule.body_regex_any):
        return ()
    if any(re.search(pattern, body, flags=re.IGNORECASE) for pattern in rule.body_regex_none):
        return ()
    if rule.header_any and not any(pattern.casefold() in headers_folded for pattern in rule.header_any):
        return ()
    if any(pattern.casefold() in headers_folded for pattern in rule.header_none):
        return ()
    matched = [f'status:{response.status}' for _ in rule.status_codes]
    matched.extend(f'body:{pattern}' for pattern in rule.body_all)
    matched.extend(f'body:{pattern}' for pattern in rule.body_any if pattern.casefold() in body_folded)
    matched.extend(f'body-regex:{pattern}' for pattern in rule.body_regex_all)
    matched.extend(f'body-regex:{pattern}' for pattern in rule.body_regex_any if re.search(pattern, body, flags=re.IGNORECASE))
    matched.extend(f'header:{pattern}' for pattern in rule.header_any if pattern.casefold() in headers_folded)
    return tuple(sorted(set(matched)))


class TakeoverScanner:
    """Collect provider-gated takeover indicators without claiming provider resources."""

    def __init__(
        self,
        hosts: Iterable[object],
        *,
        target: str,
        nameservers: Iterable[str],
        concurrency: int = DEFAULT_TAKEOVER_CONCURRENCY,
        rules: tuple[TakeoverRule, ...] = TAKEOVER_RULES,
    ) -> None:
        if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency <= 0:
            raise ValueError('takeover concurrency must be greater than zero')
        self.target = normalize_hostname(target)
        self.hosts = tuple(
            sorted({hostname for value in hosts if (hostname := _candidate_hostname(value, self.target)) is not None})
        )
        self.nameservers = tuple(sorted({str(ipaddress.ip_address(item)) for item in nameservers}))
        if not self.nameservers:
            raise ValueError('takeover checks require at least one resolver')
        self.concurrency = concurrency
        self.rules = validate_takeover_rules(rules)
        self.candidate_count = len(self.hosts)
        self.completed_count = 0
        self.request_count = 0
        self.request_error_count = 0
        self.dns_error_count = 0
        self.wildcard_indistinguishable_count = 0
        self.indicator_count = 0
        self.no_indicator_count = 0
        self.inconclusive_count = 0
        self.request_error_types: set[str] = set()
        self.scan_error_type: str | None = None
        self.stop_reason: str | None = None
        self._outcomes: list[TakeoverCandidateOutcome] = []

    async def _query_dns(
        self,
        hostname: str,
        resolvers: tuple[TakeoverDNSResolver, ...],
    ) -> tuple[TakeoverDNSOutcome, ...]:
        outcomes: list[TakeoverDNSOutcome | None] = [None] * len(resolvers)

        async def query(index: int, resolver: TakeoverDNSResolver) -> None:
            try:
                outcomes[index] = await resolver.query(hostname)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                outcomes[index] = TakeoverDNSOutcome(
                    resolver=resolver.nameserver,
                    cname_chain=(),
                    terminal_rcode='ERROR',
                    error_type=type(error).__name__,
                )

        async with asyncio.TaskGroup() as group:
            for index, resolver in enumerate(resolvers):
                group.create_task(query(index, resolver), name=f'takeover-dns:{hostname}:{resolver.nameserver}')
        completed = tuple(
            sorted(
                (outcome for outcome in outcomes if outcome is not None),
                key=TakeoverDNSOutcome.sort_key,
            )
        )
        self.dns_error_count += sum(item.terminal_rcode == 'ERROR' or item.error_type is not None for item in completed)
        self.request_error_types.update(item.error_type for item in completed if item.error_type is not None)
        return completed

    async def _fetch_http(
        self,
        hostname: str,
        scheme: HttpScheme,
        session: aiohttp.ClientSession,
    ) -> tuple[TakeoverHTTPOutcome, FetcherResponse | None]:
        self.request_count += 1
        try:
            response = await AsyncFetcher.fetch_text(
                f'{scheme}://{hostname}',
                session=session,
                follow_redirects=False,
                request_timeout=None,
                response_byte_limit=MAX_TAKEOVER_RESPONSE_BYTES,
            )
        except asyncio.CancelledError:
            raise
        except ResponseStreamError as error:
            error_type = 'ResponseLimitError' if error.reason == 'response-limit' else 'TransportError'
            self.request_error_count += 1
            self.request_error_types.add(error_type)
            return (
                TakeoverHTTPOutcome(
                    scheme=scheme,
                    status=error.status,
                    location=error.headers.get('location'),
                    error_type=error_type,
                    body_truncated=error.reason == 'response-limit',
                ),
                None,
            )
        return (
            TakeoverHTTPOutcome(
                scheme=scheme,
                status=response.status,
                location=response.headers.get('location'),
            ),
            response,
        )

    async def _scan_candidate(
        self,
        hostname: str,
        resolvers: tuple[TakeoverDNSResolver, ...],
        session: aiohttp.ClientSession,
    ) -> None:
        dns_outcomes = await self._query_dns(hostname, resolvers)
        error_types = _dns_outcome_errors(dns_outcomes)
        if error_types:
            self._record_outcome(
                TakeoverCandidateOutcome(
                    hostname=hostname,
                    status='inconclusive',
                    dns=dns_outcomes,
                    error_types=tuple(sorted(error_types)),
                )
            )
            return
        candidate_rules = tuple(rule for rule in self.rules if all(_rule_matches_dns(rule, item) for item in dns_outcomes))
        if _dns_outcomes_disagree(dns_outcomes) or any(
            _rule_has_resolver_disagreement(rule, dns_outcomes) for rule in self.rules
        ):
            self._record_outcome(
                TakeoverCandidateOutcome(
                    hostname=hostname,
                    status='inconclusive',
                    dns=dns_outcomes,
                    error_types=('ResolverDisagreementError',),
                )
            )
            return
        if not candidate_rules:
            self._record_outcome(TakeoverCandidateOutcome(hostname=hostname, status='no-indicator', dns=dns_outcomes))
            return
        wildcard_outcomes = await self._query_dns(_wildcard_probe_hostname(hostname, self.target), resolvers)
        wildcard_errors = _dns_outcome_errors(wildcard_outcomes)
        if _dns_outcomes_disagree(wildcard_outcomes):
            wildcard_errors.add('WildcardDisagreementError')
        if wildcard_errors:
            wildcard_errors.add('WildcardControlError')
            self._record_outcome(
                TakeoverCandidateOutcome(
                    hostname=hostname,
                    status='inconclusive',
                    dns=dns_outcomes,
                    wildcard_dns=wildcard_outcomes,
                    error_types=tuple(sorted(wildcard_errors)),
                )
            )
            return
        retained_rules: list[TakeoverRule] = []
        for rule in candidate_rules:
            wildcard_state = _wildcard_rule_state(rule, dns_outcomes, wildcard_outcomes)
            if wildcard_state == 'distinct':
                retained_rules.append(rule)
                continue
            error_types.add(
                'WildcardIndistinguishableError' if wildcard_state == 'indistinguishable' else 'WildcardDisagreementError'
            )
        if not retained_rules:
            self.wildcard_indistinguishable_count += 1
            self.stop_reason = 'wildcard-indistinguishable'
            self._record_outcome(
                TakeoverCandidateOutcome(
                    hostname=hostname,
                    status='inconclusive',
                    dns=dns_outcomes,
                    wildcard_dns=wildcard_outcomes,
                    error_types=tuple(sorted(error_types)),
                )
            )
            return
        indicators: list[TakeoverIndicator] = []
        dns_rules = tuple(rule for rule in retained_rules if rule.terminal_rcodes)
        for rule in dns_rules:
            matching_terminal = [outcome.terminal_rcode in rule.terminal_rcodes for outcome in dns_outcomes]
            if all(matching_terminal):
                indicators.append(
                    TakeoverIndicator(
                        classification=rule.classification,
                        service=rule.service,
                        rule_id=rule.rule_id,
                        rule_revision=TAKEOVER_RULE_REVISION,
                        matched=tuple(sorted(f'dns:terminal-rcode={rcode}' for rcode in rule.terminal_rcodes)),
                    )
                )
            elif any(matching_terminal):
                error_types.add('ResolverDisagreementError')
        http_rules = tuple(rule for rule in retained_rules if not rule.terminal_rcodes)
        if not http_rules:
            self._record_evaluated_outcome(hostname, dns_outcomes, wildcard_outcomes, (), indicators, error_types)
            return
        fetched: list[tuple[TakeoverHTTPOutcome, FetcherResponse | None] | None] = [None, None]

        async def fetch(index: int, scheme: HttpScheme) -> None:
            fetched[index] = await self._fetch_http(hostname, scheme, session)

        schemes: tuple[HttpScheme, ...] = ('https', 'http')
        async with asyncio.TaskGroup() as group:
            for index, scheme in enumerate(schemes):
                group.create_task(fetch(index, scheme), name=f'takeover-http:{hostname}:{scheme}')
        http_outcomes = tuple(
            sorted(
                (item[0] for item in fetched if item is not None),
                key=TakeoverHTTPOutcome.sort_key,
            )
        )
        for rule in http_rules:
            for item in fetched:
                if item is None or item[1] is None:
                    continue
                matched = _match_http(rule, item[1])
                if not matched:
                    continue
                indicators.append(
                    TakeoverIndicator(
                        classification=rule.classification,
                        service=rule.service,
                        rule_id=rule.rule_id,
                        rule_revision=TAKEOVER_RULE_REVISION,
                        scheme=item[0].scheme,
                        matched=matched,
                    )
                )
                break
        error_types.update(item.error_type for item in http_outcomes if item.error_type is not None)
        self._record_evaluated_outcome(
            hostname,
            dns_outcomes,
            wildcard_outcomes,
            http_outcomes,
            indicators,
            error_types,
        )

    def _record_evaluated_outcome(
        self,
        hostname: str,
        dns: tuple[TakeoverDNSOutcome, ...],
        wildcard_dns: tuple[TakeoverDNSOutcome, ...],
        http: tuple[TakeoverHTTPOutcome, ...],
        indicators: list[TakeoverIndicator],
        error_types: set[str],
    ) -> None:
        canonical_indicators = tuple(sorted(set(indicators), key=TakeoverIndicator.sort_key))
        status: TakeoverCandidateStatus = (
            'indicator' if canonical_indicators else 'inconclusive' if error_types else 'no-indicator'
        )
        self._record_outcome(
            TakeoverCandidateOutcome(
                hostname=hostname,
                status=status,
                dns=dns,
                wildcard_dns=wildcard_dns,
                http=http,
                indicators=canonical_indicators,
                error_types=tuple(sorted(error_types)),
            )
        )

    def _record_outcome(self, outcome: TakeoverCandidateOutcome) -> None:
        self._outcomes.append(outcome)
        self.request_error_types.update(outcome.error_types)
        if outcome.status == 'indicator':
            self.indicator_count += 1
            for indicator in outcome.indicators:
                output_logger.info(
                    f'\t Takeover {indicator.classification}: {outcome.hostname} ({indicator.service}, rule {indicator.rule_id})'
                )
        elif outcome.status == 'no-indicator':
            self.no_indicator_count += 1
        else:
            self.inconclusive_count += 1
            output_logger.info(f'\t Takeover check inconclusive for {outcome.hostname}: {", ".join(outcome.error_types)}')

    async def process(self, proxy: bool = False) -> None:
        self.completed_count = 0
        self.request_count = 0
        self.request_error_count = 0
        self.dns_error_count = 0
        self.wildcard_indistinguishable_count = 0
        self.indicator_count = 0
        self.no_indicator_count = 0
        self.inconclusive_count = 0
        self.request_error_types.clear()
        self.scan_error_type = None
        self.stop_reason = None
        self._outcomes.clear()
        resolvers: tuple[TakeoverDNSResolver, ...] = ()
        session: aiohttp.ClientSession | None = None
        candidates = iter(self.hosts)
        cancellation: asyncio.CancelledError | None = None
        phase_error: Exception | None = None

        async def worker() -> None:
            for hostname in candidates:
                try:
                    assert session is not None
                    await self._scan_candidate(hostname, resolvers, session)
                finally:
                    self.completed_count += 1

        try:
            ssl_context = AsyncFetcher._ssl_context()
            proxy_url, proxy_type = AsyncFetcher._resolve_proxy(proxy)
            session = await AsyncFetcher._build_session(
                {'User-Agent': Core.get_browser_user_agent()},
                aiohttp.ClientTimeout(total=None),
                proxy_url,
                proxy_type,
                ssl_context,
                cookie_jar=aiohttp.DummyCookieJar(),
            )
            resolvers = tuple(TakeoverDNSResolver(nameserver) for nameserver in self.nameservers)
            async with asyncio.TaskGroup() as group:
                for index in range(min(self.concurrency, self.candidate_count)):
                    group.create_task(worker(), name=f'takeover-worker:{index}')
        except asyncio.CancelledError as error:
            self.scan_error_type = 'CancelledError'
            self.stop_reason = 'cancelled'
            cancellation = error
        except Exception as error:
            phase_error = error
            self.scan_error_type = type(error).__name__
            self.stop_reason = 'scan-error'

        close_tasks = [
            asyncio.create_task(resolver.close(), name=f'takeover-resolver-close:{resolver.nameserver}') for resolver in resolvers
        ]
        if session is not None:
            close_tasks.append(asyncio.create_task(session.close(), name='takeover-http-session-close'))
        interruptions = await drain_tasks_after_cancellation(close_tasks, cancel=False)
        close_errors = tuple(task for task in close_tasks if not task.cancelled() and task.exception() is not None)
        if cancellation is not None:
            raise cancellation
        if interruptions:
            raise interruptions[0]
        if phase_error is not None:
            return
        if close_errors:
            close_task = close_errors[0]
            close_error = close_task.exception()
            assert close_error is not None
            self.scan_error_type = type(close_error).__name__
            self.stop_reason = (
                'http-session-close-error' if close_task.get_name() == 'takeover-http-session-close' else 'resolver-close-error'
            )
        elif self.inconclusive_count and self.stop_reason is None:
            self.stop_reason = 'incomplete-candidates'

    async def get_takeover_outcomes(self) -> tuple[TakeoverCandidateOutcome, ...]:
        return canonical_takeover_outcomes(self._outcomes)
