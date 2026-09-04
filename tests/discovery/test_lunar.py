#!/usr/bin/env python3
"""
Tests for the Lunar Domain Exposure discovery module.

Lunar exposes a free, keyless domain-exposure endpoint that aggregates
infostealer-log and data-breach intelligence for a given domain:

    https://api.lunarcyber.com/domain-exposure?domain=example.com

The module extracts hostnames and interesting URLs from the report's
``top_login_urls`` and keeps a flattened exposure summary.
"""

from unittest.mock import AsyncMock

import pytest

from theHarvester.discovery import lunar


# =============================================================================
# 1. Initialization and structure
# =============================================================================
class TestLunarInitialization:
    def test_init_normalizes_word(self) -> None:
        search = lunar.SearchLunar('  Example.COM  ')
        assert search.word == 'example.com'

    def test_init_creates_empty_collections(self) -> None:
        search = lunar.SearchLunar('example.com')
        assert search.totalhosts == set()
        assert search.interesting_urls == set()
        assert search.exposure == {}
        assert search.malware_families == []

    def test_init_proxy_default_false(self) -> None:
        search = lunar.SearchLunar('example.com')
        assert search.proxy is False

    def test_class_has_required_methods(self) -> None:
        search = lunar.SearchLunar('example.com')
        for method in ('do_search', 'get_hostnames', 'get_interestingurls', 'process'):
            assert hasattr(search, method)
            assert callable(getattr(search, method))


# =============================================================================
# 2. Report parsing (offline, no network)
# =============================================================================
class TestLunarReportParsing:
    @staticmethod
    def _sample_report() -> dict:
        return {
            'domain': 'example.com',
            'generated_at': '2026-08-01T00:00:00',
            'summary': {
                'total_events': 100,
                'infostealer_events': 30,
                'data_breach_events': 70,
                'employee_events': 90,
                'client_events': 10,
                'first_seen': '2025-08-01',
                'last_seen': '2026-07-31',
            },
            'infostealer_summary': {'malware_families_observed': 2},
            'data_breach_summary': {'known_breach_sources_count': 5},
            'malware_family_breakdown': [
                {'family': 'Redline', 'events': 20},
                {'family': 'LummaC2', 'events': 10},
            ],
            'top_login_urls': [
                {'url': 'sts.example.com', 'events': 50},
                {'url': 'https://vpn.example.com/login', 'events': 40},
                {'url': 'portal.example.com/adfs/**/', 'events': 30},
                {'url': 'unrelated.example', 'events': 5},
                {'url': '*.wildcard.example.com', 'events': 1},
            ],
        }

    def test_parse_report_extracts_target_hosts(self) -> None:
        search = lunar.SearchLunar('example.com')
        search._parse_report(self._sample_report())
        # Hostnames belonging to the target domain are captured, wildcards and
        # unrelated domains are excluded.
        assert 'sts.example.com' in search.totalhosts
        assert 'vpn.example.com' in search.totalhosts
        assert 'portal.example.com' in search.totalhosts
        assert 'unrelated.example' not in search.totalhosts
        assert all('*' not in host for host in search.totalhosts)

    def test_parse_report_keeps_all_login_urls(self) -> None:
        search = lunar.SearchLunar('example.com')
        search._parse_report(self._sample_report())
        # Every parseable login URL is retained as an interesting URL, even if
        # it belongs to an unrelated domain.
        assert 'sts.example.com' in search.interesting_urls
        assert 'https://vpn.example.com/login' in search.interesting_urls
        assert 'unrelated.example' in search.interesting_urls

    def test_parse_report_builds_summary(self) -> None:
        search = lunar.SearchLunar('example.com')
        search._parse_report(self._sample_report())
        assert search.exposure['total_events'] == 100
        assert search.exposure['infostealer_events'] == 30
        assert search.exposure['data_breach_events'] == 70
        assert search.exposure['malware_families_observed'] == 2
        assert search.exposure['known_breach_sources_count'] == 5

    def test_parse_report_captures_malware_families(self) -> None:
        search = lunar.SearchLunar('example.com')
        search._parse_report(self._sample_report())
        families = {entry['family'] for entry in search.malware_families}
        assert families == {'Redline', 'LummaC2'}

    def test_parse_empty_report_is_safe(self) -> None:
        search = lunar.SearchLunar('example.com')
        search._parse_report({})
        assert search.totalhosts == set()
        assert search.interesting_urls == set()


# =============================================================================
# 3. Async getter contracts (offline)
# =============================================================================
class TestLunarGetters:
    @pytest.mark.asyncio
    async def test_get_hostnames_returns_set(self) -> None:
        search = lunar.SearchLunar('example.com')
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_get_interestingurls_returns_sorted_list(self) -> None:
        search = lunar.SearchLunar('example.com')
        search.interesting_urls = {'b.example.com', 'a.example.com'}
        result = await search.get_interestingurls()
        assert result == ['a.example.com', 'b.example.com']

    @pytest.mark.asyncio
    async def test_get_exposure_returns_dict(self) -> None:
        search = lunar.SearchLunar('example.com')
        result = await search.get_exposure()
        assert isinstance(result, dict)


# =============================================================================
# 4. Process contract (offline)
# =============================================================================
class TestLunarProcess:
    @pytest.mark.asyncio
    @pytest.mark.parametrize('target', ['example.test', 'www.example.test'])
    async def test_process_preserves_reported_www_hostname(self, monkeypatch: pytest.MonkeyPatch, target: str) -> None:
        report = {
            'status': 'REPORT_READY',
            'report': {'top_login_urls': [{'url': 'https://www.example.test/login'}]},
        }
        monkeypatch.setattr(lunar.AsyncFetcher, 'fetch_all', AsyncMock(return_value=[report]))
        search = lunar.SearchLunar(target)

        await search.process()

        assert await search.get_hostnames() == {'www.example.test'}
        assert await search.get_interestingurls() == ['https://www.example.test/login']


if __name__ == '__main__':
    pytest.main()
