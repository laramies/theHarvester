from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from theHarvester.discovery import (
    apisguru,
    arquivo,
    baidusearch,
    bevigil,
    bravesearch,
    bufferoverun,
    builtwith,
    censysearch,
    certspottersearch,
    commoncrawl,
    criminalip,
    crtname,
    crtsh,
    dnsdb,
    duckduckgosearch,
    dymosearch,
    fofa,
    fullhuntsearch,
    githubcode,
    gitlabsearch,
    hackertarget,
    haveibeenpwned,
    hibpverified,
    hudsonrocksearch,
    huntersearch,
    intelxsearch,
    leakix,
    leaklookup,
    mojeek,
    netlas,
    onyphe,
    otxsearch,
    pentesttools,
    projectdiscovery,
    rapiddns,
    robtex,
    rocketreach,
    search_dehashed,
    search_dnsdumpster,
    searchhunterhow,
    securityscorecard,
    securitytrailssearch,
    sherlockeye,
    shodan_internetdb,
    shodanct,
    shodansearch,
    sourcegraph,
    subdomainapi,
    subdomaincenter,
    subdomainfinderc99,
    thc,
    tombasearch,
    urlscan,
    virustotal,
    waybackarchive,
    whoisxml,
    windvane,
    yahoosearch,
    zoomeyesearch,
)
from theHarvester.discovery.constants import MissingKeyError
from theHarvester.lib.asn_attribution import AsnAttributionObservation, canonical_asn_attributions
from theHarvester.lib.completed_result import ResultKind, ResultObservation, SourceExecution
from theHarvester.lib.core import AsyncFetcher, ProxyUnavailableError
from theHarvester.lib.enumeration import DEFAULT_SOURCE_WORKERS
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.result_values import normalize_ip
from theHarvester.lib.shodan_evidence import ShodanHostObservation, canonical_shodan_hosts
from theHarvester.lib.source_catalog import ResultRoute, get_source_spec
from theHarvester.lib.source_execution import SourceExecutionReport

if TYPE_CHECKING:
    from theHarvester.lib.evidence_types import ExecutionStatus

logger = logging.getLogger(__name__)

SourceFactory = Callable[['SourceRequest'], Any]
SourceStarted = Callable[['SourceRequest'], None]
OutcomeCommit = Callable[['SourceOutcome'], None]
OutcomeAfterCommit = Callable[['SourceOutcome'], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class SourceRequest:
    """Normalized inputs needed to construct and run one discovery source."""

    source: str
    target: str
    limit: int | None
    start: int
    proxy: bool
    include_hostnames: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, 'source', get_source_spec(self.source).name)


@dataclass(frozen=True, slots=True)
class SourceOutcome:
    """Immutable evidence and execution status produced by one source."""

    execution: SourceExecution
    observations: tuple[ResultObservation, ...] = ()
    asn_attributions: tuple[AsnAttributionObservation, ...] = ()
    shodan_hosts: tuple[ShodanHostObservation, ...] = ()
    reported_host_ip_pairs: tuple[tuple[str, str], ...] = ()


SOURCE_FACTORIES: dict[str, SourceFactory] = {
    'apis-guru': lambda request: apisguru.SearchApisGuru(request.target, request.limit),
    'arquivo': lambda request: arquivo.SearchArquivo(request.target, request.limit),
    'baidu': lambda request: baidusearch.SearchBaidu(request.target, request.limit),
    'bevigil': lambda request: bevigil.SearchBeVigil(request.target),
    'brave': lambda request: bravesearch.SearchBrave(request.target, request.limit),
    'bufferoverun': lambda request: bufferoverun.SearchBufferover(request.target),
    'builtwith': lambda request: builtwith.SearchBuiltWith(request.target),
    'censys': lambda request: censysearch.SearchCensys(request.target, request.limit),
    'certspotter': lambda request: certspottersearch.SearchCertspoter(request.target),
    'commoncrawl': lambda request: commoncrawl.SearchCommoncrawl(request.target, request.limit),
    'criminalip': lambda request: criminalip.SearchCriminalIP(request.target),
    'crt-name': lambda request: crtname.SearchCrtName(request.target),
    'crtsh': lambda request: crtsh.SearchCrtsh(request.target),
    'dehashed': lambda request: search_dehashed.SearchDehashed(request.target, limit=request.limit),
    'dnsdb': lambda request: dnsdb.SearchDNSDB(request.target),
    'dnsdumpster': lambda request: search_dnsdumpster.SearchDNSDumpster(request.target),
    'duckduckgo': lambda request: duckduckgosearch.SearchDuckDuckGo(request.target, request.limit),
    'dymo': lambda request: dymosearch.SearchDymo(request.target),
    'fofa': lambda request: fofa.SearchFofa(request.target, request.limit),
    'fullhunt': lambda request: fullhuntsearch.SearchFullHunt(request.target),
    'github-code': lambda request: githubcode.SearchGithubCode(request.target, request.limit),
    'gitlab': lambda request: gitlabsearch.SearchGitlab(request.target, request.limit),
    'hackertarget': lambda request: hackertarget.SearchHackerTarget(request.target),
    'haveibeenpwned': lambda request: haveibeenpwned.SearchHaveIBeenPwned(request.target),
    'hibpverified': lambda request: hibpverified.SearchHibpVerified(request.target),
    'hudsonrock': lambda request: hudsonrocksearch.SearchHudsonRock(request.target),
    'hunter': lambda request: huntersearch.SearchHunter(request.target, request.limit, request.start),
    'hunterhow': lambda request: searchhunterhow.SearchHunterHow(request.target, request.limit),
    'intelx': lambda request: intelxsearch.SearchIntelx(request.target, request.limit),
    'leakix': lambda request: leakix.SearchLeakix(request.target),
    'leaklookup': lambda request: leaklookup.SearchLeakLookup(request.target),
    'mojeek': lambda request: mojeek.SearchMojeek(request.target, request.limit),
    'netlas': lambda request: netlas.SearchNetlas(request.target, request.limit),
    'onyphe': lambda request: onyphe.SearchOnyphe(request.target, request.limit),
    'otx': lambda request: otxsearch.SearchOtx(request.target),
    'pentesttools': lambda request: pentesttools.SearchPentestTools(request.target),
    'projectdiscovery': lambda request: projectdiscovery.SearchDiscovery(request.target),
    'rapiddns': lambda request: rapiddns.SearchRapidDns(request.target),
    'robtex': lambda request: robtex.SearchRobtex(request.target),
    'rocketreach': lambda request: rocketreach.SearchRocketReach(request.target, request.limit),
    'securityTrails': lambda request: securitytrailssearch.SearchSecuritytrail(request.target),
    'securityscorecard': lambda request: securityscorecard.SearchSecurityScorecard(request.target, request.limit),
    'sherlockeye': lambda request: sherlockeye.SearchSherlockeye(request.target),
    'shodan': lambda request: shodansearch.SearchShodan(request.target),
    'shodanInternetDB': lambda request: shodan_internetdb.SearchShodanInternetDB(request.target),
    'shodanct': lambda request: shodanct.SearchShodanCt(request.target),
    'sourcegraph': lambda request: sourcegraph.SearchSourcegraph(request.target, request.limit),
    'subdomainapi': lambda request: subdomainapi.SearchSubdomainApi(request.target),
    'subdomaincenter': lambda request: subdomaincenter.SubdomainCenter(request.target),
    'subdomainfinderc99': lambda request: subdomainfinderc99.SearchSubdomainfinderc99(request.target),
    'thc': lambda request: thc.SearchThc(request.target, request.limit),
    'tomba': lambda request: tombasearch.SearchTomba(request.target, request.limit, request.start),
    'urlscan': lambda request: urlscan.SearchUrlscan(request.target, request.limit),
    'virustotal': lambda request: virustotal.SearchVirustotal(request.target, request.limit),
    'waybackarchive': lambda request: waybackarchive.SearchWaybackarchive(request.target, request.limit),
    'whoisxml': lambda request: whoisxml.SearchWhoisXML(request.target, request.limit),
    'windvane': lambda request: windvane.SearchWindvane(request.target, request.limit),
    'yahoo': lambda request: yahoosearch.SearchYahoo(request.target, request.limit),
    'zoomeye': lambda request: zoomeyesearch.SearchZoomEye(request.target, request.limit),
}


_ROUTE_GETTERS: dict[ResultRoute, tuple[str, ResultKind]] = {
    ResultRoute.SUBDOMAINS: ('get_hostnames', 'hostname'),
    ResultRoute.EMAILS: ('get_emails', 'email'),
    ResultRoute.IPS: ('get_ips', 'ip'),
    ResultRoute.PEOPLE: ('get_people', 'person'),
    ResultRoute.URLS: ('get_urls', 'url'),
    ResultRoute.ASNS: ('get_asns', 'asn'),
    ResultRoute.BREACHES: ('get_breach_names', 'breach'),
}
_BUILTWITH_GETTERS: tuple[tuple[str, ResultKind], ...] = (
    ('get_frameworks', 'framework'),
    ('get_languages', 'language'),
    ('get_servers', 'server'),
    ('get_cms', 'cms'),
    ('get_analytics', 'analytics'),
)


def _normalize_values(request: SourceRequest, kind: ResultKind, values: Iterable[object]) -> set[ResultObservation]:
    observations: set[ResultObservation] = set()
    canonical_target = normalize_scoped_hostname(request.target, request.target)
    for item in values:
        if kind == 'hostname':
            value = normalize_scoped_hostname(item, request.target)
            if value is None or value == canonical_target:
                continue
        elif kind == 'email':
            value = str(item).strip().lower()
            if not value:
                continue
        elif kind == 'ip':
            try:
                value = normalize_ip(str(item))
            except ValueError:
                continue
        elif kind in {'infostealer', 'person'}:
            value = json.dumps(item, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
        else:
            value = str(item).strip()
            if not value:
                continue
        observations.add(ResultObservation(request.source, kind, value))
    return observations


def create_source(request: SourceRequest) -> Any:
    """Construct the catalog-backed adapter for a source request."""

    return SOURCE_FACTORIES[get_source_spec(request.source).name](request)


def _reject_removed_execution_fields(source: str, adapter: Any) -> None:
    fields = tuple(name for name in ('execution_status', 'stop_reason') if hasattr(adapter, name))
    if fields:
        raise ValueError(f'Source {source} exposes removed mutable execution fields: {", ".join(fields)}')


async def _collect_observations(
    request: SourceRequest,
    adapter: Any,
    observations: set[ResultObservation],
    asn_attributions: set[AsnAttributionObservation],
    shodan_hosts: set[ShodanHostObservation],
    reported_host_ip_pairs: set[tuple[str, str]],
) -> None:
    source_spec = get_source_spec(request.source)
    for route, (getter_name, kind) in _ROUTE_GETTERS.items():
        if route not in source_spec.routes or (route is ResultRoute.SUBDOMAINS and not request.include_hostnames):
            continue
        observations.update(_normalize_values(request, kind, await getattr(adapter, getter_name)()))
    if ResultRoute.ASNS in source_spec.routes and (getter := getattr(adapter, 'get_asn_attributions', None)):
        asn_attributions.update(await getter())
    if request.source == 'builtwith':
        for getter_name, kind in _BUILTWITH_GETTERS:
            observations.update(_normalize_values(request, kind, await getattr(adapter, getter_name)()))
    elif request.source == 'hudsonrock':
        observations.update(_normalize_values(request, 'infostealer', await adapter.get_infostealers()))
    elif request.source == 'shodan':
        shodan_hosts.update(canonical_shodan_hosts(list(await adapter.get_shodan_hosts())))
        observations.update(ResultObservation(request.source, 'shodan-host', host.ip) for host in shodan_hosts)
    if request.source == 'rapiddns':
        for host, address in await adapter.get_host_ip_pairs():
            normalized_host = normalize_scoped_hostname(host, request.target)
            try:
                normalized_address = normalize_ip(str(address))
            except ValueError:
                continue
            if (
                normalized_host
                and ResultObservation(request.source, 'hostname', normalized_host) in observations
                and ResultObservation(request.source, 'ip', normalized_address) in observations
            ):
                reported_host_ip_pairs.add((normalized_host, normalized_address))


def _source_outcome(
    request: SourceRequest,
    execution: SourceExecution,
    observations: set[ResultObservation],
    asn_attributions: set[AsnAttributionObservation],
    shodan_hosts: set[ShodanHostObservation],
    reported_host_ip_pairs: set[tuple[str, str]],
) -> SourceOutcome:
    accepted_attributions = (
        attribution
        for attribution in asn_attributions
        if ResultObservation(request.source, 'asn', attribution.asn) in observations
        and ResultObservation(request.source, attribution.subject_kind, attribution.subject_value) in observations
    )
    return SourceOutcome(
        execution,
        tuple(sorted(observations)),
        canonical_asn_attributions(list(accepted_attributions)),
        canonical_shodan_hosts(list(shodan_hosts)),
        tuple(sorted(reported_host_ip_pairs)),
    )


async def run_source(
    request: SourceRequest,
    *,
    commit_cancelled: OutcomeCommit | None = None,
    on_started: SourceStarted | None = None,
) -> SourceOutcome:
    """Run one adapter and return its normalized evidence without leaking provider errors."""

    started = time.perf_counter()
    observations: set[ResultObservation] = set()
    asn_attributions: set[AsnAttributionObservation] = set()
    shodan_hosts: set[ShodanHostObservation] = set()
    reported_host_ip_pairs: set[tuple[str, str]] = set()
    adapter: Any | None = None
    process_completed = False
    try:
        with AsyncFetcher.proxy_scope(request.proxy) as selected_proxy:
            source_spec = get_source_spec(request.source)
            created_adapter = create_source(request)
            _reject_removed_execution_fields(source_spec.name, created_adapter)
            if on_started is not None:
                try:
                    on_started(request)
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    logger.warning('Source start reporter failed for %s: %s', request.source, type(error).__name__)
            adapter = created_adapter
            report = await adapter.process(selected_proxy)
        process_completed = True
        _reject_removed_execution_fields(source_spec.name, adapter)
        if report is None:
            status: ExecutionStatus = 'completed'
            stop_reason = None
        elif isinstance(report, SourceExecutionReport):
            status = report.status
            stop_reason = report.stop_reason
        else:
            raise ValueError(f'Source {source_spec.name} returned invalid execution report: {report!r}')
        await _collect_observations(
            request,
            adapter,
            observations,
            asn_attributions,
            shodan_hosts,
            reported_host_ip_pairs,
        )
        result_count = len(observations)
        if result_count and status != 'completed':
            status = 'partial'
        elif not result_count and status == 'completed' and stop_reason is None:
            stop_reason = 'no-results'
        execution = SourceExecution(
            source_spec.name,
            status,
            (time.perf_counter() - started) * 1000,
            result_count,
            stop_reason=stop_reason,
        )
    except ProxyUnavailableError:
        execution = SourceExecution(
            request.source,
            'failed',
            (time.perf_counter() - started) * 1000,
            0,
            'ProxyUnavailableError',
            'proxy-unavailable',
        )
    except MissingKeyError:
        execution = SourceExecution(
            request.source,
            'skipped',
            (time.perf_counter() - started) * 1000,
            0,
            'MissingKeyError',
            'missing-credentials',
        )
    except asyncio.CancelledError:
        if adapter is not None and not process_completed:
            try:
                _reject_removed_execution_fields(request.source, adapter)
                await _collect_observations(
                    request,
                    adapter,
                    observations,
                    asn_attributions,
                    shodan_hosts,
                    reported_host_ip_pairs,
                )
            except Exception:
                pass
        result_count = len(observations)
        outcome = _source_outcome(
            request,
            SourceExecution(
                request.source,
                'partial' if result_count else 'failed',
                (time.perf_counter() - started) * 1000,
                result_count,
                'CancelledError',
                'cancelled',
            ),
            observations,
            asn_attributions,
            shodan_hosts,
            reported_host_ip_pairs,
        )
        if commit_cancelled is not None:
            commit_cancelled(outcome)
        raise
    except Exception as error:
        if adapter is not None and not process_completed:
            try:
                _reject_removed_execution_fields(request.source, adapter)
                await _collect_observations(
                    request,
                    adapter,
                    observations,
                    asn_attributions,
                    shodan_hosts,
                    reported_host_ip_pairs,
                )
            except Exception:
                pass
        result_count = len(observations)
        execution = SourceExecution(
            request.source,
            'partial' if result_count else 'failed',
            (time.perf_counter() - started) * 1000,
            result_count,
            type(error).__name__,
        )
    return _source_outcome(
        request,
        execution,
        observations,
        asn_attributions,
        shodan_hosts,
        reported_host_ip_pairs,
    )


async def run_source_jobs(
    jobs: tuple[SourceRequest, ...],
    *,
    workers: int = DEFAULT_SOURCE_WORKERS,
    commit: OutcomeCommit | None = None,
    after_commit: OutcomeAfterCommit | None = None,
    on_started: SourceStarted | None = None,
) -> tuple[SourceOutcome, ...]:
    """Run every job through a bounded TaskGroup worker pool and preserve input order."""

    if isinstance(workers, bool) or not isinstance(workers, int) or workers <= 0:
        raise ValueError('source workers must be a positive integer')
    outcomes: list[SourceOutcome | None] = [None] * len(jobs)
    owned_tasks: list[asyncio.Task[None]] = []
    primary_cancellation: asyncio.CancelledError | None = None
    next_index = 0

    def commit_cancelled(index: int, outcome: SourceOutcome) -> None:
        outcomes[index] = outcome
        if commit is not None:
            commit(outcome)

    async def worker() -> None:
        nonlocal next_index, primary_cancellation

        while next_index < len(jobs):
            index = next_index
            next_index += 1
            request = jobs[index]

            def commit_current_cancelled(outcome: SourceOutcome, current_index: int = index) -> None:
                commit_cancelled(current_index, outcome)

            try:
                outcome = await run_source(
                    request,
                    commit_cancelled=commit_current_cancelled,
                    on_started=on_started,
                )
                outcomes[index] = outcome
                if commit is not None:
                    commit(outcome)
                if after_commit is not None:
                    await after_commit(outcome)
            except asyncio.CancelledError as error:
                if primary_cancellation is None:
                    primary_cancellation = error
                if outcomes[index] is None:
                    commit_cancelled(
                        index,
                        SourceOutcome(SourceExecution(request.source, 'failed', 0, 0, 'CancelledError', 'cancelled')),
                    )
                current_task = asyncio.current_task()
                for task in owned_tasks:
                    if task is not current_task and not task.done():
                        task.cancel()
                raise

    caught_cancellation: asyncio.CancelledError | None = None
    try:
        async with asyncio.TaskGroup() as group:
            for index in range(min(workers, len(jobs))):
                owned_tasks.append(group.create_task(worker(), name=f'source-worker:{index}'))
    except asyncio.CancelledError as error:
        caught_cancellation = error

    if primary_cancellation is not None or caught_cancellation is not None:
        cancellation = caught_cancellation or primary_cancellation
        for index, outcome in enumerate(outcomes):
            if outcome is None:
                request = jobs[index]
                commit_cancelled(
                    index,
                    SourceOutcome(SourceExecution(request.source, 'failed', 0, 0, 'CancelledError', 'cancelled')),
                )
        assert cancellation is not None
        raise cancellation
    return tuple(outcome for outcome in outcomes if outcome is not None)
