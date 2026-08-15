import asyncio
from types import SimpleNamespace

import pytest

from theHarvester.discovery import takeover
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.takeover_evidence import TakeoverCandidateOutcome, TakeoverDNSOutcome
from theHarvester.lib.takeover_rules import TakeoverRule


@pytest.mark.asyncio
async def test_takeover_requires_provider_dns_evidence_and_compound_http_predicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dns_outcomes = {
        'bucket.example.test': TakeoverDNSOutcome(
            resolver='1.1.1.1',
            cname_chain=('missing-bucket.s3.amazonaws.com',),
            terminal_rcode='NOERROR',
        ),
        'generic.example.test': TakeoverDNSOutcome(
            resolver='1.1.1.1',
            cname_chain=('generic.invalid',),
            terminal_rcode='NOERROR',
        ),
    }

    class FakeResolver:
        def __init__(self, nameserver: str) -> None:
            assert nameserver == '1.1.1.1'
            self.nameserver = nameserver

        async def query(self, hostname: str) -> TakeoverDNSOutcome:
            return dns_outcomes.get(
                hostname,
                TakeoverDNSOutcome(
                    resolver=self.nameserver,
                    cname_chain=(),
                    terminal_rcode='NXDOMAIN',
                ),
            )

        async def close(self) -> None:
            return None

    requested: list[str] = []

    async def fake_fetch_text(url: str, **kwargs: object) -> FetcherResponse:
        requested.append(url)
        assert kwargs['follow_redirects'] is False
        assert kwargs['response_byte_limit'] == takeover.MAX_TAKEOVER_RESPONSE_BYTES
        return FetcherResponse(
            body='<Code>NoSuchBucket</Code><BucketName>missing-bucket</BucketName>The specified bucket does not exist',
            status=404,
            headers={'content-type': 'application/xml'},
        )

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', FakeResolver)
    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_text', fake_fetch_text)

    scanner = takeover.TakeoverScanner(
        ['bucket.example.test', 'generic.example.test:192.0.2.10'],
        target='example.test',
        nameservers=['1.1.1.1'],
    )
    await scanner.process()

    outcomes = await scanner.get_takeover_outcomes()
    assert [outcome.hostname for outcome in outcomes] == ['bucket.example.test', 'generic.example.test']
    bucket, generic = outcomes
    assert bucket.status == 'indicator'
    assert bucket.indicators[0].service == 'AWS/S3'
    assert bucket.indicators[0].classification == 'vulnerable-indicator'
    assert bucket.indicators[0].scheme == 'https'
    assert bucket.http[0].status == 404
    assert set(bucket.indicators[0].matched) == {
        'body:The specified bucket does not exist',
        'body:BucketName',
    }
    assert generic.status == 'no-indicator'
    assert generic.indicators == ()
    assert set(requested) == {'https://bucket.example.test', 'http://bucket.example.test'}
    assert scanner.candidate_count == 2
    assert scanner.completed_count == 2
    assert scanner.request_count == 2
    assert scanner.request_error_count == 0


@pytest.mark.asyncio
async def test_takeover_keeps_dns_only_nxdomain_evidence_without_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, _hostname: str) -> TakeoverDNSOutcome:
            if _hostname.startswith('takeover-control-'):
                return TakeoverDNSOutcome(
                    resolver=self.nameserver,
                    cname_chain=(),
                    terminal_rcode='NXDOMAIN',
                )
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=('missing.eu-west-1.elasticbeanstalk.com',),
                terminal_rcode='NXDOMAIN',
            )

        async def close(self) -> None:
            return None

    async def unexpected_fetch(*_args: object, **_kwargs: object) -> FetcherResponse:
        raise AssertionError('DNS-only rule must not send an HTTP request')

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', FakeResolver)
    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_text', unexpected_fetch)

    scanner = takeover.TakeoverScanner(
        ['app.example.test'],
        target='example.test',
        nameservers=['1.1.1.1', '8.8.8.8'],
    )
    await scanner.process()

    outcome = (await scanner.get_takeover_outcomes())[0]
    assert outcome.status == 'indicator'
    assert outcome.indicators[0].service == 'AWS/Elastic Beanstalk'
    assert outcome.indicators[0].matched == ('dns:terminal-rcode=NXDOMAIN',)
    assert {item.resolver for item in outcome.dns} == {'1.1.1.1', '8.8.8.8'}
    assert scanner.request_count == 0


@pytest.mark.asyncio
async def test_takeover_fails_closed_when_proxy_mode_has_no_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(takeover.AsyncFetcher, '_resolve_proxy', lambda _proxy: (None, None))
    scanner = takeover.TakeoverScanner(
        ['app.example.test'],
        target='example.test',
        nameservers=['1.1.1.1'],
    )

    await scanner.process(proxy=True)

    assert await scanner.get_takeover_outcomes() == ()
    assert scanner.scan_error_type == 'ProxyUnavailableError'
    assert scanner.stop_reason == 'proxy-unavailable'
    assert scanner.completed_count == 0


@pytest.mark.asyncio
async def test_takeover_response_limit_is_partial_and_does_not_stop_siblings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, hostname: str) -> TakeoverDNSOutcome:
            if hostname.startswith('takeover-control-'):
                return TakeoverDNSOutcome(
                    resolver=self.nameserver,
                    cname_chain=(),
                    terminal_rcode='NXDOMAIN',
                )
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=(f'{hostname.split(".")[0]}.s3.amazonaws.com',),
                terminal_rcode='NOERROR',
            )

        async def close(self) -> None:
            return None

    async def fake_fetch_text(url: str, **_kwargs: object) -> FetcherResponse:
        if 'large.' in url:
            raise ResponseStreamError('response-limit', status=200, headers={'location': '/retained'})
        return FetcherResponse(
            body='The specified bucket does not exist <BucketName>valid</BucketName>',
            status=404,
            headers={},
        )

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', FakeResolver)
    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_text', fake_fetch_text)
    scanner = takeover.TakeoverScanner(
        ['large.example.test', 'valid.example.test'],
        target='example.test',
        nameservers=['1.1.1.1'],
    )

    await scanner.process()

    outcomes = await scanner.get_takeover_outcomes()
    assert [item.hostname for item in outcomes] == ['large.example.test', 'valid.example.test']
    assert [item.status for item in outcomes] == ['inconclusive', 'indicator']
    assert outcomes[0].error_types == ('ResponseLimitError',)
    assert {item.location for item in outcomes[0].http} == {'/retained'}
    assert scanner.completed_count == 2
    assert scanner.request_error_count == 2
    assert scanner.request_error_types == {'ResponseLimitError'}


@pytest.mark.asyncio
async def test_takeover_suppresses_provider_like_wildcard_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    class WildcardResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, _hostname: str) -> TakeoverDNSOutcome:
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=('wildcard.s3.amazonaws.com',),
                terminal_rcode='NOERROR',
            )

        async def close(self) -> None:
            return None

    async def unexpected_fetch(*_args: object, **_kwargs: object) -> FetcherResponse:
        raise AssertionError('wildcard-indistinguishable DNS must not trigger HTTP')

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', WildcardResolver)
    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_text', unexpected_fetch)
    scanner = takeover.TakeoverScanner(
        ['bucket.example.test'],
        target='example.test',
        nameservers=['1.1.1.1'],
    )

    await scanner.process()

    outcomes = await scanner.get_takeover_outcomes()
    assert len(outcomes) == 1
    assert outcomes[0].status == 'inconclusive'
    assert outcomes[0].error_types == ('WildcardIndistinguishableError',)
    assert scanner.wildcard_indistinguishable_count == 1
    assert scanner.stop_reason == 'wildcard-indistinguishable'
    assert scanner.request_count == 0


@pytest.mark.asyncio
async def test_takeover_keeps_distinct_provider_cnames_separate_from_wildcard_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DistinctWildcardResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, hostname: str) -> TakeoverDNSOutcome:
            cname = (
                'wildcard-bucket.s3.amazonaws.com' if hostname.startswith('takeover-control-') else 'real-bucket.s3.amazonaws.com'
            )
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=(cname,),
                terminal_rcode='NOERROR',
            )

        async def close(self) -> None:
            return None

    async def fake_fetch_text(_url: str, **_kwargs: object) -> FetcherResponse:
        return FetcherResponse(
            body='The specified bucket does not exist <BucketName>real-bucket</BucketName>',
            status=404,
            headers={},
        )

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', DistinctWildcardResolver)
    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_text', fake_fetch_text)
    scanner = takeover.TakeoverScanner(
        ['bucket.example.test'],
        target='example.test',
        nameservers=['1.1.1.1'],
    )

    await scanner.process()

    outcome = (await scanner.get_takeover_outcomes())[0]
    assert outcome.status == 'indicator'
    assert outcome.dns[0].cname_chain == ('real-bucket.s3.amazonaws.com',)
    assert outcome.wildcard_dns[0].cname_chain == ('wildcard-bucket.s3.amazonaws.com',)


@pytest.mark.asyncio
async def test_takeover_wildcard_control_failure_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailedControlResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, hostname: str) -> TakeoverDNSOutcome:
            if hostname.startswith('takeover-control-'):
                return TakeoverDNSOutcome(
                    resolver=self.nameserver,
                    cname_chain=(),
                    terminal_rcode='ERROR',
                    error_type='TimeoutError',
                )
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=('bucket.s3.amazonaws.com',),
                terminal_rcode='NOERROR',
            )

        async def close(self) -> None:
            return None

    async def unexpected_fetch(*_args: object, **_kwargs: object) -> FetcherResponse:
        raise AssertionError('failed wildcard controls must not trigger HTTP')

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', FailedControlResolver)
    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_text', unexpected_fetch)
    scanner = takeover.TakeoverScanner(
        ['bucket.example.test'],
        target='example.test',
        nameservers=['1.1.1.1'],
    )

    await scanner.process()

    outcome = (await scanner.get_takeover_outcomes())[0]
    assert outcome.status == 'inconclusive'
    assert outcome.error_types == ('TimeoutError', 'WildcardControlError')
    assert outcome.wildcard_dns[0].error_type == 'TimeoutError'


@pytest.mark.asyncio
async def test_takeover_marks_resolver_disagreement_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    class DisagreeingResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, _hostname: str) -> TakeoverDNSOutcome:
            cname = 'bucket.s3.amazonaws.com' if self.nameserver == '1.1.1.1' else 'live.provider.example'
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=(cname,),
                terminal_rcode='NOERROR',
            )

        async def close(self) -> None:
            return None

    async def unexpected_fetch(*_args: object, **_kwargs: object) -> FetcherResponse:
        raise AssertionError('resolver disagreement must not trigger HTTP')

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', DisagreeingResolver)
    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_text', unexpected_fetch)
    scanner = takeover.TakeoverScanner(
        ['bucket.example.test'],
        target='example.test',
        nameservers=['1.1.1.1', '8.8.8.8'],
    )

    await scanner.process()

    outcome = (await scanner.get_takeover_outcomes())[0]
    assert outcome.status == 'inconclusive'
    assert outcome.error_types == ('ResolverDisagreementError',)
    assert scanner.inconclusive_count == 1
    assert scanner.stop_reason == 'incomplete-candidates'


@pytest.mark.asyncio
async def test_takeover_dns_only_rule_requires_terminal_rcode_agreement(monkeypatch: pytest.MonkeyPatch) -> None:
    class ConflictingRcodeResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, _hostname: str) -> TakeoverDNSOutcome:
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=('missing.elasticbeanstalk.com',),
                terminal_rcode='NXDOMAIN' if self.nameserver == '1.1.1.1' else 'NOERROR',
            )

        async def close(self) -> None:
            return None

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', ConflictingRcodeResolver)
    scanner = takeover.TakeoverScanner(
        ['app.example.test'],
        target='example.test',
        nameservers=['1.1.1.1', '8.8.8.8'],
    )

    await scanner.process()

    outcome = (await scanner.get_takeover_outcomes())[0]
    assert outcome.status == 'inconclusive'
    assert outcome.error_types == ('ResolverDisagreementError',)
    assert outcome.indicators == ()


@pytest.mark.asyncio
async def test_takeover_wildcard_control_stays_in_the_authorized_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    queried: list[str] = []

    class ScopedResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, hostname: str) -> TakeoverDNSOutcome:
            queried.append(hostname)
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=() if hostname.startswith('takeover-control-') else ('bucket.s3.amazonaws.com',),
                terminal_rcode='NXDOMAIN' if hostname.startswith('takeover-control-') else 'NOERROR',
            )

        async def close(self) -> None:
            return None

    async def fake_fetch_text(_url: str, **_kwargs: object) -> FetcherResponse:
        return FetcherResponse(
            body='The specified bucket does not exist <BucketName>bucket</BucketName>',
            status=404,
            headers={},
        )

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', ScopedResolver)
    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_text', fake_fetch_text)
    scanner = takeover.TakeoverScanner(
        ['example.co.uk'],
        target='example.co.uk',
        nameservers=['1.1.1.1'],
    )

    await scanner.process()

    control = next(hostname for hostname in queried if hostname.startswith('takeover-control-'))
    assert control.endswith('.example.co.uk')
    assert (await scanner.get_takeover_outcomes())[0].status == 'indicator'


@pytest.mark.asyncio
async def test_takeover_distinguishes_nodata_from_required_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    class NodataResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, hostname: str) -> TakeoverDNSOutcome:
            return TakeoverDNSOutcome(
                resolver=self.nameserver,
                cname_chain=() if hostname.startswith('takeover-control-') else ('missing.elasticbeanstalk.com',),
                terminal_rcode='NXDOMAIN' if hostname.startswith('takeover-control-') else 'NODATA',
            )

        async def close(self) -> None:
            return None

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', NodataResolver)
    scanner = takeover.TakeoverScanner(
        ['app.example.test'],
        target='example.test',
        nameservers=['1.1.1.1'],
    )

    await scanner.process()

    outcome = (await scanner.get_takeover_outcomes())[0]
    assert outcome.status == 'no-indicator'
    assert outcome.indicators == ()


def test_takeover_rule_language_validates_regex_and_all_classifications() -> None:
    rule = TakeoverRule(
        'regex-rule',
        'Regex Provider',
        (r'(?:^|\.)provider\.example$',),
        body_regex_all=(r'account\s+not\s+found',),
    )
    response = FetcherResponse(body='ACCOUNT  not   found', status=404, headers={})

    assert takeover._match_http(rule, response) == ('body-regex:account\\s+not\\s+found',)
    with pytest.raises(ValueError, match='invalid regular expression'):
        TakeoverRule('bad-regex', 'Bad Regex', ('[',), body_all=('missing',))
    with pytest.raises(ValueError, match='cannot mix DNS and HTTP predicates'):
        TakeoverRule(
            'mixed-rule',
            'Mixed Provider',
            (r'(?:^|\.)provider\.example$',),
            terminal_rcodes=('NXDOMAIN',),
            body_all=('missing',),
        )
    assert {rule.classification for rule in takeover.TAKEOVER_RULES} == {
        'vulnerable-indicator',
        'unverified-indicator',
        'edge-case',
    }


@pytest.mark.asyncio
async def test_takeover_dns_resolver_retains_partial_query_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class PartialResolver:
        def __init__(self, *, nameservers: list[str]) -> None:
            assert nameservers == ['1.1.1.1']

        async def query_dns(self, _hostname: str, record_type: str) -> object:
            if record_type == 'A':
                return SimpleNamespace(answer=[SimpleNamespace(data=SimpleNamespace(addr='192.0.2.10'))])
            if record_type == 'AAAA':
                raise takeover.aiodns.error.DNSError(takeover.aiodns.error.ARES_ENODATA, 'no IPv6 data')
            raise takeover.aiodns.error.DNSError(takeover.aiodns.error.ARES_ETIMEOUT, 'CNAME timed out')

        async def close(self) -> None:
            return None

    monkeypatch.setattr(takeover.aiodns, 'DNSResolver', PartialResolver)

    resolver = takeover.TakeoverDNSResolver('1.1.1.1')
    outcome = await resolver.query('app.example.test')
    await resolver.close()

    assert outcome.terminal_rcode == 'NOERROR'
    assert outcome.error_type == 'DNSError'


def test_takeover_evidence_rejects_runtime_impossible_records() -> None:
    dns = {
        'resolver': '1.1.1.1',
        'cname_chain': ['bucket.s3.amazonaws.com'],
        'terminal_rcode': 'NOERROR',
    }
    base = {
        'status': 'no-indicator',
        'dns': [dns],
        'wildcard_dns': [],
        'http': [],
        'indicators': [],
        'error_types': [],
    }

    with pytest.raises(ValueError, match='one DNS outcome per resolver'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'dns': [dns, {**dns, 'terminal_rcode': 'NXDOMAIN'}],
            },
        )
    with pytest.raises(ValueError, match='one HTTP outcome per scheme'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'http': [
                    {'scheme': 'https', 'status': 404},
                    {'scheme': 'https', 'status': 503},
                ],
            },
        )
    with pytest.raises(ValueError, match='response status or error type'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'http': [{'scheme': 'https'}],
            },
        )
    with pytest.raises(ValueError, match='DNS ERROR outcomes require an error type'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'dns': [{**dns, 'terminal_rcode': 'ERROR'}],
            },
        )
    with pytest.raises(ValueError, match='include every DNS and HTTP outcome error'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'http': [{'scheme': 'https', 'error_type': 'TransportError'}],
                'wildcard_dns': [
                    {
                        'resolver': '1.1.1.1',
                        'cname_chain': [],
                        'terminal_rcode': 'NXDOMAIN',
                    }
                ],
            },
        )
    with pytest.raises(ValueError, match='wildcard control per resolver'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'http': [{'scheme': 'https', 'status': 404}],
            },
        )
    with pytest.raises(ValueError, match='candidate DNS agreement across resolvers'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'dns': [
                    dns,
                    {
                        'resolver': '8.8.8.8',
                        'cname_chain': ['different.s3.amazonaws.com'],
                        'terminal_rcode': 'NOERROR',
                    },
                ],
                'wildcard_dns': [
                    {
                        'resolver': '1.1.1.1',
                        'cname_chain': [],
                        'terminal_rcode': 'NXDOMAIN',
                    },
                    {
                        'resolver': '8.8.8.8',
                        'cname_chain': [],
                        'terminal_rcode': 'NXDOMAIN',
                    },
                ],
                'http': [{'scheme': 'https', 'status': 404}],
            },
        )
    with pytest.raises(ValueError, match='wildcard DNS agreement across resolvers'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'dns': [dns, {**dns, 'resolver': '8.8.8.8'}],
                'wildcard_dns': [
                    {
                        'resolver': '1.1.1.1',
                        'cname_chain': [],
                        'terminal_rcode': 'NXDOMAIN',
                    },
                    {
                        'resolver': '8.8.8.8',
                        'cname_chain': ['wildcard.s3.amazonaws.com'],
                        'terminal_rcode': 'NOERROR',
                    },
                ],
                'http': [{'scheme': 'https', 'status': 404}],
            },
        )
    with pytest.raises(ValueError, match='successful outcome for their matching scheme'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'status': 'indicator',
                'wildcard_dns': [
                    {
                        'resolver': '1.1.1.1',
                        'cname_chain': [],
                        'terminal_rcode': 'NXDOMAIN',
                    }
                ],
                'http': [{'scheme': 'http', 'status': 404}],
                'indicators': [
                    {
                        'classification': 'vulnerable-indicator',
                        'service': 'AWS/S3',
                        'rule_id': 'aws-s3',
                        'rule_revision': 'takeover-rules-v1',
                        'scheme': 'https',
                        'matched': ['body:BucketName'],
                    }
                ],
            },
        )
    with pytest.raises(ValueError, match='cannot mix DNS and HTTP predicates'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'status': 'indicator',
                'http': [{'scheme': 'https', 'status': 404}],
                'indicators': [
                    {
                        'classification': 'vulnerable-indicator',
                        'service': 'AWS/S3',
                        'rule_id': 'aws-s3',
                        'rule_revision': 'takeover-rules-v1',
                        'scheme': 'https',
                        'matched': ['body:BucketName', 'dns:terminal-rcode=NOERROR'],
                    }
                ],
            },
        )
    with pytest.raises(ValueError, match='wildcard control per resolver'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'status': 'indicator',
                'http': [{'scheme': 'https', 'status': 404}],
                'indicators': [
                    {
                        'classification': 'vulnerable-indicator',
                        'service': 'AWS/S3',
                        'rule_id': 'aws-s3',
                        'rule_revision': 'takeover-rules-v1',
                        'scheme': 'https',
                        'matched': ['body:BucketName'],
                    }
                ],
            },
        )
    wildcard = {
        'resolver': '1.1.1.1',
        'cname_chain': [],
        'terminal_rcode': 'NXDOMAIN',
    }
    with pytest.raises(ValueError, match='agree with every resolver outcome'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'status': 'indicator',
                'wildcard_dns': [wildcard],
                'indicators': [
                    {
                        'classification': 'vulnerable-indicator',
                        'service': 'AWS/Elastic Beanstalk',
                        'rule_id': 'aws-elastic-beanstalk',
                        'rule_revision': 'takeover-rules-v1',
                        'matched': ['dns:terminal-rcode=NXDOMAIN'],
                    }
                ],
            },
        )
    with pytest.raises(ValueError, match='status predicates must agree'):
        TakeoverCandidateOutcome.from_record(
            'bucket.example.test',
            {
                **base,
                'status': 'indicator',
                'wildcard_dns': [wildcard],
                'http': [{'scheme': 'https', 'status': 404}],
                'indicators': [
                    {
                        'classification': 'unverified-indicator',
                        'service': 'Helprace',
                        'rule_id': 'helprace',
                        'rule_revision': 'takeover-rules-v1',
                        'scheme': 'https',
                        'matched': ['status:301'],
                    }
                ],
            },
        )


@pytest.mark.asyncio
async def test_takeover_cancellation_closes_resolvers_and_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    started = asyncio.Event()
    closed = asyncio.Event()

    class BlockingResolver:
        def __init__(self, nameserver: str) -> None:
            self.nameserver = nameserver

        async def query(self, _hostname: str) -> TakeoverDNSOutcome:
            started.set()
            await asyncio.Event().wait()
            raise AssertionError('unreachable')

        async def close(self) -> None:
            closed.set()

    monkeypatch.setattr(takeover, 'TakeoverDNSResolver', BlockingResolver)
    scanner = takeover.TakeoverScanner(
        ['app.example.test'],
        target='example.test',
        nameservers=['1.1.1.1'],
    )
    task = asyncio.create_task(scanner.process())
    await started.wait()

    task.cancel('operator-stop')
    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await task

    assert closed.is_set()
    assert not [task for task in asyncio.all_tasks() if task.get_name().startswith('takeover-')]
