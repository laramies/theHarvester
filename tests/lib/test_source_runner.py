from __future__ import annotations

import asyncio
import logging
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import Any

import pytest

from theHarvester.discovery.constants import MissingKeyError
from theHarvester.lib.asn_attribution import AsnAttributionObservation
from theHarvester.lib.completed_result import ResultObservation, SourceExecution
from theHarvester.lib.source_catalog import SOURCE_SPECS
from theHarvester.lib.source_runner import (
    SOURCE_FACTORIES,
    SourceJob,
    SourceOutcome,
    SourceRequest,
    create_source,
    run_source,
    run_source_jobs,
)


@pytest.mark.parametrize('workers', [0, -1, True, 1.5])
@pytest.mark.asyncio
async def test_source_jobs_require_a_positive_worker_count(workers: object) -> None:
    with pytest.raises(ValueError, match='source workers must be a positive integer'):
        await run_source_jobs((), workers=workers)  # type: ignore[arg-type]


def test_source_contracts_are_immutable() -> None:
    request = SourceRequest('APIS-GURU', 'example.test', 25, 5, True, True)
    job = SourceJob(request)
    outcome = SourceOutcome(SourceExecution('apis-guru', 'completed', 0, 0))

    with pytest.raises(FrozenInstanceError):
        request.target = 'changed.test'  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        job.request = request  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        outcome.observations = ()  # type: ignore[misc]
    assert request.source == 'apis-guru'


def test_source_factories_match_the_catalog() -> None:
    assert set(SOURCE_FACTORIES) == set(SOURCE_SPECS)


@pytest.mark.parametrize(
    ('source', 'patch_target', 'expected_args', 'expected_kwargs'),
    [
        ('apis-guru', 'theHarvester.lib.source_runner.apisguru.SearchApisGuru', ('example.test', 25), {}),
        ('arquivo', 'theHarvester.lib.source_runner.arquivo.SearchArquivo', ('example.test', 25), {}),
        ('baidu', 'theHarvester.lib.source_runner.baidusearch.SearchBaidu', ('example.test', 25), {}),
        ('bevigil', 'theHarvester.lib.source_runner.bevigil.SearchBeVigil', ('example.test',), {}),
        ('brave', 'theHarvester.lib.source_runner.bravesearch.SearchBrave', ('example.test', 25), {}),
        ('bufferoverun', 'theHarvester.lib.source_runner.bufferoverun.SearchBufferover', ('example.test',), {}),
        ('builtwith', 'theHarvester.lib.source_runner.builtwith.SearchBuiltWith', ('example.test',), {}),
        ('censys', 'theHarvester.lib.source_runner.censysearch.SearchCensys', ('example.test', 25), {}),
        ('certspotter', 'theHarvester.lib.source_runner.certspottersearch.SearchCertspoter', ('example.test',), {}),
        ('commoncrawl', 'theHarvester.lib.source_runner.commoncrawl.SearchCommoncrawl', ('example.test', 25), {}),
        ('criminalip', 'theHarvester.lib.source_runner.criminalip.SearchCriminalIP', ('example.test',), {}),
        ('crt-name', 'theHarvester.lib.source_runner.crtname.SearchCrtName', ('example.test',), {}),
        ('crtsh', 'theHarvester.lib.source_runner.crtsh.SearchCrtsh', ('example.test',), {}),
        ('dehashed', 'theHarvester.lib.source_runner.search_dehashed.SearchDehashed', ('example.test',), {'limit': 25}),
        ('dnsdb', 'theHarvester.lib.source_runner.dnsdb.SearchDNSDB', ('example.test',), {}),
        (
            'dnsdumpster',
            'theHarvester.lib.source_runner.search_dnsdumpster.SearchDNSDumpster',
            ('example.test',),
            {},
        ),
        ('duckduckgo', 'theHarvester.lib.source_runner.duckduckgosearch.SearchDuckDuckGo', ('example.test', 25), {}),
        ('dymo', 'theHarvester.lib.source_runner.dymosearch.SearchDymo', ('example.test',), {}),
        ('fofa', 'theHarvester.lib.source_runner.fofa.SearchFofa', ('example.test', 25), {}),
        ('fullhunt', 'theHarvester.lib.source_runner.fullhuntsearch.SearchFullHunt', ('example.test',), {}),
        ('github-code', 'theHarvester.lib.source_runner.githubcode.SearchGithubCode', ('example.test', 25), {}),
        ('gitlab', 'theHarvester.lib.source_runner.gitlabsearch.SearchGitlab', ('example.test',), {}),
        (
            'hackertarget',
            'theHarvester.lib.source_runner.hackertarget.SearchHackerTarget',
            ('example.test',),
            {},
        ),
        (
            'haveibeenpwned',
            'theHarvester.lib.source_runner.haveibeenpwned.SearchHaveIBeenPwned',
            ('example.test',),
            {},
        ),
        (
            'hibpverified',
            'theHarvester.lib.source_runner.hibpverified.SearchHibpVerified',
            ('example.test',),
            {},
        ),
        ('hudsonrock', 'theHarvester.lib.source_runner.hudsonrocksearch.SearchHudsonRock', ('example.test',), {}),
        ('hunter', 'theHarvester.lib.source_runner.huntersearch.SearchHunter', ('example.test', 25, 5), {}),
        ('hunterhow', 'theHarvester.lib.source_runner.searchhunterhow.SearchHunterHow', ('example.test', 25), {}),
        ('intelx', 'theHarvester.lib.source_runner.intelxsearch.SearchIntelx', ('example.test',), {}),
        ('leakix', 'theHarvester.lib.source_runner.leakix.SearchLeakix', ('example.test',), {}),
        ('leaklookup', 'theHarvester.lib.source_runner.leaklookup.SearchLeakLookup', ('example.test',), {}),
        ('mojeek', 'theHarvester.lib.source_runner.mojeek.SearchMojeek', ('example.test', 25), {}),
        ('netlas', 'theHarvester.lib.source_runner.netlas.SearchNetlas', ('example.test', 25), {}),
        ('onyphe', 'theHarvester.lib.source_runner.onyphe.SearchOnyphe', ('example.test', 25), {}),
        ('otx', 'theHarvester.lib.source_runner.otxsearch.SearchOtx', ('example.test',), {}),
        (
            'pentesttools',
            'theHarvester.lib.source_runner.pentesttools.SearchPentestTools',
            ('example.test',),
            {},
        ),
        (
            'projectdiscovery',
            'theHarvester.lib.source_runner.projectdiscovery.SearchDiscovery',
            ('example.test',),
            {},
        ),
        ('rapiddns', 'theHarvester.lib.source_runner.rapiddns.SearchRapidDns', ('example.test',), {}),
        ('robtex', 'theHarvester.lib.source_runner.robtex.SearchRobtex', ('example.test',), {}),
        ('rocketreach', 'theHarvester.lib.source_runner.rocketreach.SearchRocketReach', ('example.test', 25), {}),
        (
            'securityTrails',
            'theHarvester.lib.source_runner.securitytrailssearch.SearchSecuritytrail',
            ('example.test',),
            {},
        ),
        (
            'securityscorecard',
            'theHarvester.lib.source_runner.securityscorecard.SearchSecurityScorecard',
            ('example.test', 25),
            {},
        ),
        (
            'sherlockeye',
            'theHarvester.lib.source_runner.sherlockeye.SearchSherlockeye',
            ('example.test',),
            {},
        ),
        ('shodan', 'theHarvester.lib.source_runner.shodansearch.SearchShodan', ('example.test',), {}),
        (
            'shodanInternetDB',
            'theHarvester.lib.source_runner.shodan_internetdb.SearchShodanInternetDB',
            ('example.test',),
            {},
        ),
        ('shodanct', 'theHarvester.lib.source_runner.shodanct.SearchShodanCt', ('example.test',), {}),
        ('sourcegraph', 'theHarvester.lib.source_runner.sourcegraph.SearchSourcegraph', ('example.test', 25), {}),
        (
            'subdomaincenter',
            'theHarvester.lib.source_runner.subdomaincenter.SubdomainCenter',
            ('example.test',),
            {},
        ),
        (
            'subdomainfinderc99',
            'theHarvester.lib.source_runner.subdomainfinderc99.SearchSubdomainfinderc99',
            ('example.test',),
            {},
        ),
        ('thc', 'theHarvester.lib.source_runner.thc.SearchThc', ('example.test',), {}),
        ('tomba', 'theHarvester.lib.source_runner.tombasearch.SearchTomba', ('example.test', 25, 5), {}),
        ('urlscan', 'theHarvester.lib.source_runner.urlscan.SearchUrlscan', ('example.test',), {}),
        ('virustotal', 'theHarvester.lib.source_runner.virustotal.SearchVirustotal', ('example.test', 25), {}),
        (
            'waybackarchive',
            'theHarvester.lib.source_runner.waybackarchive.SearchWaybackarchive',
            ('example.test', 25),
            {},
        ),
        ('whoisxml', 'theHarvester.lib.source_runner.whoisxml.SearchWhoisXML', ('example.test', 25), {}),
        ('windvane', 'theHarvester.lib.source_runner.windvane.SearchWindvane', ('example.test',), {}),
        ('yahoo', 'theHarvester.lib.source_runner.yahoosearch.SearchYahoo', ('example.test', 25), {}),
        ('zoomeye', 'theHarvester.lib.source_runner.zoomeyesearch.SearchZoomEye', ('example.test', 25), {}),
    ],
)
def test_factory_constructor_shapes(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    patch_target: str,
    expected_args: tuple[object, ...],
    expected_kwargs: dict[str, object],
) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def constructor(*args: object, **kwargs: object) -> object:
        calls.append((args, kwargs))
        return object()

    monkeypatch.setattr(patch_target, constructor)

    create_source(SourceRequest(source, 'example.test', 25, 5, True, False))

    assert calls == [(expected_args, expected_kwargs)]


@pytest.mark.asyncio
async def test_runner_normalizes_only_declared_apis_guru_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeApisGuru:
        execution_status = 'completed'
        stop_reason = None

        def __init__(self, target: str, limit: int) -> None:
            assert (target, limit) == ('example.test', 25)

        async def process(self, proxy: bool) -> None:
            assert proxy is True

        async def get_hostnames(self) -> list[str]:
            return ['API.Example.TEST.', 'api.example.test', 'outside.test', 'example.test']

        async def get_emails(self) -> list[str]:
            return ['User@Example.TEST', 'user@example.test']

        async def get_urls(self) -> list[str]:
            return ['https://api.example.test/v1', 'https://api.example.test/v1']

        async def get_ips(self) -> set[str]:
            raise AssertionError('undeclared getter must not be read')

    monkeypatch.setitem(SOURCE_FACTORIES, 'apis-guru', lambda request: FakeApisGuru(request.target, request.limit))

    outcome = await run_source(SourceRequest('apis-guru', 'example.test', 25, 5, True, True))

    assert outcome.execution.source == 'apis-guru'
    assert outcome.execution.status == 'completed'
    assert outcome.execution.result_count == 3
    assert outcome.execution.stop_reason is None
    assert outcome.observations == (
        ResultObservation('apis-guru', 'email', 'user@example.test'),
        ResultObservation('apis-guru', 'hostname', 'api.example.test'),
        ResultObservation('apis-guru', 'url', 'https://api.example.test/v1'),
    )
    assert outcome.asn_attributions == ()


@pytest.mark.asyncio
async def test_runner_times_construction_and_records_missing_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter((10.0, 10.125))
    events: list[str] = []

    def clock() -> float:
        events.append('clock')
        return next(ticks)

    def missing_factory(_request: SourceRequest) -> Any:
        assert events == ['clock']
        raise MissingKeyError('apis-guru')

    monkeypatch.setattr('theHarvester.lib.source_runner.time.perf_counter', clock)
    monkeypatch.setitem(SOURCE_FACTORIES, 'apis-guru', missing_factory)

    outcome = await run_source(SourceRequest('apis-guru', 'example.test', 25, 0, False, True))

    assert outcome.execution == SourceExecution(
        'apis-guru',
        'skipped',
        125,
        0,
        'MissingKeyError',
        'missing-credentials',
    )


@pytest.mark.asyncio
async def test_start_reporter_failure_is_sanitized_and_does_not_change_provider_outcome(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    process_called = False

    class SuccessfulAdapter:
        async def process(self, _proxy: bool) -> None:
            nonlocal process_called
            process_called = True

        async def get_hostnames(self) -> set[str]:
            return {'fresh.example.test'}

        async def get_emails(self) -> set[str]:
            return set()

        async def get_ips(self) -> set[str]:
            return set()

        async def get_urls(self) -> set[str]:
            return set()

    def broken_reporter(_request: SourceRequest) -> None:
        raise RuntimeError('sensitive callback payload')

    monkeypatch.setitem(SOURCE_FACTORIES, 'apis-guru', lambda _request: SuccessfulAdapter())
    caplog.set_level(logging.WARNING, logger='theHarvester.lib.source_runner')

    outcome = await run_source(
        SourceRequest('apis-guru', 'example.test', 25, 0, False, True),
        on_started=broken_reporter,
    )

    assert process_called is True
    assert outcome.execution.status == 'completed'
    assert outcome.execution.error_type is None
    assert outcome.observations == (ResultObservation('apis-guru', 'hostname', 'fresh.example.test'),)
    assert 'Source start reporter failed for apis-guru: RuntimeError' in caplog.text
    assert 'sensitive callback payload' not in caplog.text


@pytest.mark.asyncio
async def test_start_reporter_cancellation_propagates_without_collecting_pre_process_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancellation = asyncio.CancelledError('reporter cancelled')
    committed: list[SourceOutcome] = []
    process_called = False
    getter_called = False

    class UnstartedAdapter:
        async def process(self, _proxy: bool) -> None:
            nonlocal process_called
            process_called = True

        async def get_hostnames(self) -> set[str]:
            nonlocal getter_called
            getter_called = True
            return {'stale.example.test'}

    def cancelled_reporter(_request: SourceRequest) -> None:
        raise cancellation

    monkeypatch.setitem(SOURCE_FACTORIES, 'apis-guru', lambda _request: UnstartedAdapter())

    with pytest.raises(asyncio.CancelledError) as raised:
        await run_source(
            SourceRequest('apis-guru', 'example.test', 25, 0, False, True),
            commit_cancelled=committed.append,
            on_started=cancelled_reporter,
        )

    assert raised.value is cancellation
    assert process_called is False
    assert getter_called is False
    assert committed[0].execution.status == 'failed'
    assert committed[0].execution.stop_reason == 'cancelled'
    assert committed[0].observations == ()


@pytest.mark.asyncio
async def test_runner_retains_earlier_observations_when_a_later_getter_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PartiallyFailingApisGuru:
        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'API.Example.TEST.'}

        async def get_emails(self) -> set[str]:
            raise RuntimeError('email projection failed')

    monkeypatch.setitem(SOURCE_FACTORIES, 'apis-guru', lambda _request: PartiallyFailingApisGuru())

    outcome = await run_source(SourceRequest('apis-guru', 'example.test', 25, 0, False, True))

    assert outcome.execution.status == 'partial'
    assert outcome.execution.error_type == 'RuntimeError'
    assert outcome.execution.result_count == 1
    assert outcome.observations == (ResultObservation('apis-guru', 'hostname', 'api.example.test'),)


@pytest.mark.asyncio
async def test_runner_reads_retained_adapter_evidence_after_process_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class PartiallyFailingSourcegraph:
        async def process(self, _proxy: bool) -> None:
            raise RuntimeError('stream failed')

        async def get_hostnames(self) -> set[str]:
            return {'partial.example.test'}

    monkeypatch.setitem(SOURCE_FACTORIES, 'sourcegraph', lambda _request: PartiallyFailingSourcegraph())

    outcome = await run_source(SourceRequest('sourcegraph', 'example.test', 25, 0, False, True))

    assert outcome.execution.status == 'partial'
    assert outcome.execution.error_type == 'RuntimeError'
    assert outcome.observations == (ResultObservation('sourcegraph', 'hostname', 'partial.example.test'),)


@pytest.mark.asyncio
async def test_runner_reports_normal_zero_yield_as_completed_no_results(monkeypatch: pytest.MonkeyPatch) -> None:
    class EmptySourcegraph:
        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> tuple[()]:
            return ()

    monkeypatch.setitem(SOURCE_FACTORIES, 'sourcegraph', lambda _request: EmptySourcegraph())

    outcome = await run_source(SourceRequest('sourcegraph', 'example.test', 25, 0, False, True))

    assert outcome.execution.status == 'completed'
    assert outcome.execution.stop_reason == 'no-results'
    assert outcome.execution.result_count == 0


@pytest.mark.parametrize('source', ['builtwith', 'hudsonrock', 'shodan'])
@pytest.mark.parametrize(
    ('reported_status', 'reported_reason', 'has_results', 'expected_count'),
    [
        ('completed', None, False, 0),
        ('partial', 'provider-partial', True, 1),
        ('failed', 'provider-failure', False, 0),
        ('rate-limited', 'http-429', False, 0),
    ],
)
@pytest.mark.asyncio
async def test_special_sources_share_runner_outcome_semantics(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    reported_status: str,
    reported_reason: str | None,
    has_results: bool,
    expected_count: int,
) -> None:
    class FakeSpecialSource:
        execution_status = reported_status
        stop_reason = reported_reason

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'partial.example.test'} if has_results else set()

        async def get_emails(self) -> set[str]:
            return set()

        async def get_ips(self) -> set[str]:
            return set()

        async def get_urls(self) -> set[str]:
            return set()

        async def get_frameworks(self) -> set[str]:
            return set()

        async def get_languages(self) -> set[str]:
            return set()

        async def get_servers(self) -> set[str]:
            return set()

        async def get_cms(self) -> set[str]:
            return set()

        async def get_analytics(self) -> set[str]:
            return set()

        async def get_infostealers(self) -> list[dict[str, object]]:
            return []

        async def get_shodan_hosts(self) -> tuple[()]:
            return ()

    monkeypatch.setitem(SOURCE_FACTORIES, source, lambda _request: FakeSpecialSource())

    outcome = await run_source(SourceRequest(source, 'example.test', 25, 0, False, True))

    assert outcome.execution.status == reported_status
    assert outcome.execution.stop_reason == (reported_reason or 'no-results')
    assert outcome.execution.result_count == expected_count
    assert {observation.source for observation in outcome.observations} == ({source} if has_results else set())


@pytest.mark.asyncio
async def test_runner_collects_builtwith_compatibility_observations(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeBuiltWith:
        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'app.example.test'}

        async def get_urls(self) -> set[str]:
            return {'https://app.example.test'}

        async def get_frameworks(self) -> set[str]:
            return {'Django'}

        async def get_languages(self) -> set[str]:
            return {'Python'}

        async def get_servers(self) -> set[str]:
            return {'nginx'}

        async def get_cms(self) -> set[str]:
            return {'Wagtail'}

        async def get_analytics(self) -> set[str]:
            return {'Plausible'}

    monkeypatch.setitem(SOURCE_FACTORIES, 'builtwith', lambda _request: FakeBuiltWith())

    outcome = await run_source(SourceRequest('builtwith', 'example.test', 25, 0, False, True))

    assert {(item.kind, item.value) for item in outcome.observations} == {
        ('analytics', 'Plausible'),
        ('cms', 'Wagtail'),
        ('framework', 'Django'),
        ('hostname', 'app.example.test'),
        ('language', 'Python'),
        ('server', 'nginx'),
        ('url', 'https://app.example.test'),
    }
    assert outcome.execution.result_count == 7


@pytest.mark.asyncio
async def test_runner_collects_hudson_rock_infostealers(monkeypatch: pytest.MonkeyPatch) -> None:
    infostealer = {'type': 'employee', 'url': 'https://legacy.example.test'}

    class FakeHudsonRock:
        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'portal.example.test'}

        async def get_emails(self) -> set[str]:
            return {'user@example.test'}

        async def get_ips(self) -> set[str]:
            return set()

        async def get_urls(self) -> set[str]:
            return {'https://portal.example.test'}

        async def get_infostealers(self) -> list[dict[str, object]]:
            return [infostealer]

    monkeypatch.setitem(SOURCE_FACTORIES, 'hudsonrock', lambda _request: FakeHudsonRock())

    outcome = await run_source(SourceRequest('hudsonrock', 'example.test', 25, 0, False, True))

    assert {(item.kind, item.value) for item in outcome.observations} == {
        ('email', 'user@example.test'),
        ('hostname', 'portal.example.test'),
        ('infostealer', '{"type":"employee","url":"https://legacy.example.test"}'),
    }
    assert outcome.execution.result_count == 3


@pytest.mark.asyncio
async def test_runner_keeps_only_asn_attributions_backed_by_accepted_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collected_at = datetime.now(UTC)

    class FakeOnyphe:
        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            raise AssertionError('no-hosts must not read hostname results')

        async def get_ips(self) -> set[str]:
            return {'192.0.2.1'}

        async def get_asns(self) -> set[str]:
            return {'AS64500'}

        async def get_asn_attributions(self) -> set[AsnAttributionObservation]:
            return {
                AsnAttributionObservation('source', 'onyphe', 'AS64500', 'Accepted Org', 'ip', '192.0.2.1', collected_at),
                AsnAttributionObservation('source', 'onyphe', 'AS64501', 'Wrong ASN', 'ip', '192.0.2.1', collected_at),
                AsnAttributionObservation(
                    'source', 'onyphe', 'AS64500', 'Excluded Host', 'hostname', 'host.example.test', collected_at
                ),
            }

    monkeypatch.setitem(SOURCE_FACTORIES, 'onyphe', lambda _request: FakeOnyphe())

    outcome = await run_source(SourceRequest('onyphe', 'example.test', 25, 0, False, False))

    assert len(outcome.asn_attributions) == 1
    assert outcome.asn_attributions[0].organization_label == 'Accepted Org'


@pytest.mark.asyncio
async def test_runner_reports_invalid_asn_as_partial_and_keeps_prior_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeOnyphe:
        async def process(self, _proxy: bool) -> None:
            return None

        async def get_ips(self) -> set[str]:
            return {'192.0.2.1'}

        async def get_asns(self) -> set[str]:
            return {'not-an-asn'}

    monkeypatch.setitem(SOURCE_FACTORIES, 'onyphe', lambda _request: FakeOnyphe())

    outcome = await run_source(SourceRequest('onyphe', 'example.test', 25, 0, False, False))

    assert outcome.execution.status == 'partial'
    assert outcome.execution.error_type == 'ValueError'
    assert outcome.observations == (ResultObservation('onyphe', 'ip', '192.0.2.1'),)


@pytest.mark.asyncio
async def test_runner_collects_url_before_later_asn_getter_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeZoomEye:
        async def process(self, _proxy: bool) -> None:
            return None

        async def get_emails(self) -> set[str]:
            return set()

        async def get_ips(self) -> set[str]:
            return set()

        async def get_people(self) -> set[str]:
            return set()

        async def get_urls(self) -> set[str]:
            return {'https://portal.example.test'}

        async def get_asns(self) -> set[str]:
            raise RuntimeError('asn getter failed')

    monkeypatch.setitem(SOURCE_FACTORIES, 'zoomeye', lambda _request: FakeZoomEye())

    outcome = await run_source(SourceRequest('zoomeye', 'example.test', 25, 0, False, False))

    assert outcome.execution.status == 'partial'
    assert outcome.execution.error_type == 'RuntimeError'
    assert outcome.observations == (ResultObservation('zoomeye', 'url', 'https://portal.example.test'),)


@pytest.mark.asyncio
async def test_source_jobs_use_a_clamped_worker_pool_and_isolate_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = 0
    peak = 0
    three_active = asyncio.Event()
    task_names: set[str] = set()

    class GatedAdapter:
        def __init__(self, source: str) -> None:
            self.source = source

        async def process(self, _proxy: bool) -> None:
            nonlocal active, peak
            task = asyncio.current_task()
            assert task is not None
            task_names.add(task.get_name())
            active += 1
            peak = max(peak, active)
            if active == 3:
                three_active.set()
            await three_active.wait()
            await asyncio.sleep(0)
            active -= 1
            if self.source == 'apis-guru':
                raise RuntimeError('provider failed')

        async def get_hostnames(self) -> set[str]:
            return {f'{self.source}.example.test'}

    source_names = ('apis-guru', 'sourcegraph', 'crtsh', 'crt-name')
    for source in source_names:
        monkeypatch.setitem(SOURCE_FACTORIES, source, lambda _request, source=source: GatedAdapter(source))
    jobs = tuple(SourceJob(SourceRequest(source, 'example.test', 25, 0, False, True)) for source in source_names)

    outcomes = await run_source_jobs(jobs, workers=3)

    assert peak == 3
    assert task_names == {'source-worker:0', 'source-worker:1', 'source-worker:2'}
    assert [outcome.execution.source for outcome in outcomes] == list(source_names)
    assert outcomes[0].execution.status == 'partial'
    assert outcomes[0].execution.error_type == 'RuntimeError'
    assert all(outcome.execution.status == 'completed' for outcome in outcomes[1:])
    assert not [task for task in asyncio.all_tasks() if task.get_name().startswith('source-worker:') and not task.done()]


@pytest.mark.parametrize('workers', [1, 3, 8])
@pytest.mark.asyncio
async def test_source_worker_count_does_not_change_completed_sources_or_results(
    monkeypatch: pytest.MonkeyPatch,
    workers: int,
) -> None:
    starts: list[str] = []
    task_names: set[str] = set()

    class CompleteAdapter:
        def __init__(self, source: str) -> None:
            self.source = source

        async def process(self, _proxy: bool) -> None:
            task = asyncio.current_task()
            assert task is not None
            task_names.add(task.get_name())
            starts.append(self.source)
            await asyncio.sleep(0)

        async def get_hostnames(self) -> set[str]:
            return {f'{self.source}.example.test'}

    source_names = ('apis-guru', 'sourcegraph', 'crtsh', 'crt-name')
    for source in source_names:
        monkeypatch.setitem(SOURCE_FACTORIES, source, lambda _request, source=source: CompleteAdapter(source))
    jobs = tuple(SourceJob(SourceRequest(source, 'example.test', 25, 0, False, True)) for source in source_names)

    outcomes = await run_source_jobs(jobs, workers=workers)

    assert sorted(starts) == sorted(source_names)
    assert [outcome.execution.source for outcome in outcomes] == list(source_names)
    assert [outcome.execution.result_count for outcome in outcomes] == [1, 1, 1, 1]
    assert len(task_names) == min(workers, len(jobs))


@pytest.mark.asyncio
async def test_cancelled_source_commits_immutable_partial_outcome_then_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    committed: list[SourceOutcome] = []
    cancellation = asyncio.CancelledError()

    class CancelledSourcegraph:
        async def process(self, _proxy: bool) -> None:
            raise cancellation

        async def get_hostnames(self) -> set[str]:
            return {'partial.example.test'}

    monkeypatch.setitem(SOURCE_FACTORIES, 'sourcegraph', lambda _request: CancelledSourcegraph())

    with pytest.raises(asyncio.CancelledError) as raised:
        await run_source(
            SourceRequest('sourcegraph', 'example.test', 25, 0, False, True),
            commit_cancelled=committed.append,
        )

    assert raised.value is cancellation
    assert len(committed) == 1
    outcome = committed[0]
    assert outcome.execution.status == 'partial'
    assert outcome.execution.error_type == 'CancelledError'
    assert outcome.execution.stop_reason == 'cancelled'
    assert outcome.observations == (ResultObservation('sourcegraph', 'hostname', 'partial.example.test'),)
    with pytest.raises(FrozenInstanceError):
        outcome.observations = ()  # type: ignore[misc]


@pytest.mark.asyncio
async def test_child_cancellation_promptly_cleans_blocking_sibling_and_preserves_original(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sibling_started = asyncio.Event()
    sibling_cancelled = asyncio.Event()
    cancellation = asyncio.CancelledError('source cancelled')

    class CancellingAdapter:
        async def process(self, _proxy: bool) -> None:
            await sibling_started.wait()
            raise cancellation

        async def get_hostnames(self) -> set[str]:
            return set()

    class BlockingAdapter:
        async def process(self, _proxy: bool) -> None:
            sibling_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                sibling_cancelled.set()
                raise

        async def get_hostnames(self) -> set[str]:
            return set()

    monkeypatch.setitem(SOURCE_FACTORIES, 'sourcegraph', lambda _request: CancellingAdapter())
    monkeypatch.setitem(SOURCE_FACTORIES, 'crtsh', lambda _request: BlockingAdapter())
    jobs = tuple(SourceJob(SourceRequest(source, 'example.test', 25, 0, False, True)) for source in ('crtsh', 'sourcegraph'))

    with pytest.raises(asyncio.CancelledError) as raised:
        async with asyncio.timeout(0.5):
            await run_source_jobs(jobs)

    assert raised.value is cancellation
    assert sibling_cancelled.is_set()


@pytest.mark.asyncio
async def test_parent_cancellation_commits_active_jobs_and_cleans_structured_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()
    started_count = 0
    committed: list[SourceOutcome] = []

    class BlockingAdapter:
        def __init__(self, source: str) -> None:
            self.source = source

        async def process(self, _proxy: bool) -> None:
            nonlocal started_count
            started_count += 1
            if started_count == 3:
                started.set()
            await asyncio.Event().wait()

        async def get_hostnames(self) -> set[str]:
            return {f'{self.source}.example.test'}

    source_names = ('sourcegraph', 'crtsh', 'crt-name', 'apis-guru')
    for source in source_names:
        monkeypatch.setitem(SOURCE_FACTORIES, source, lambda _request, source=source: BlockingAdapter(source))
    jobs = tuple(SourceJob(SourceRequest(source, 'example.test', 25, 0, False, True)) for source in source_names)
    task = asyncio.create_task(run_source_jobs(jobs, commit=committed.append))
    await started.wait()
    task.cancel('parent-marker')

    with pytest.raises(asyncio.CancelledError) as raised:
        await task

    assert raised.value.args == ('parent-marker',)
    assert {outcome.execution.source for outcome in committed} == set(source_names)
    assert all(outcome.execution.stop_reason == 'cancelled' for outcome in committed)
    assert not [task for task in asyncio.all_tasks() if task.get_name().startswith('source-worker:') and not task.done()]
