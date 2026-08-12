import ast
from pathlib import Path

from theHarvester.discovery import apisguru, bevigil, builtwith, gitlabsearch, intelxsearch, rocketreach, urlscan, zoomeyesearch
from theHarvester.lib.core import Core
from theHarvester.lib.source_catalog import SOURCE_SPECS, ActivityClass, ResultRoute, SourceSpec, get_source_spec


def _scheduled_source_names() -> list[str]:
    tree = ast.parse(Path('theHarvester/__main__.py').read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
            continue
        if not isinstance(node.left, ast.Name) or node.left.id != 'engineitem' or len(node.comparators) != 1:
            continue
        comparator = node.comparators[0]
        if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
            names.append(comparator.value)
    return names


def test_source_specs_cover_supported_sources() -> None:
    scheduled = _scheduled_source_names()

    assert len(scheduled) == len(set(scheduled))
    assert set(SOURCE_SPECS) == set(scheduled)
    assert set(SOURCE_SPECS) <= set(Core.get_supportedengines())


def test_dead_threatcrowd_source_is_not_selectable() -> None:
    assert 'threatcrowd' not in Core.get_supportedengines()
    assert 'threatcrowd' not in SOURCE_SPECS
    assert 'threatcrowd' not in _scheduled_source_names()


def test_invalid_bitbucket_domain_source_is_not_selectable() -> None:
    assert 'bitbucket' not in Core.get_supportedengines()
    assert 'bitbucket' not in SOURCE_SPECS
    assert 'bitbucket' not in _scheduled_source_names()


def test_subdomain_route_drives_subdomain_capability() -> None:
    spec = SourceSpec(
        name='example',
        routes=frozenset({ResultRoute.SUBDOMAINS, ResultRoute.URLS}),
    )

    assert spec.capabilities == frozenset({'subdomains', 'urls'})


def test_source_specs_describe_consolidated_routes_not_getter_presence() -> None:
    assert SOURCE_SPECS['apis-guru'].routes == frozenset(
        {ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.URLS}
    )
    assert SOURCE_SPECS['gitlab'].routes == frozenset({ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.URLS})
    assert SOURCE_SPECS['sourcegraph'].routes == frozenset({ResultRoute.SUBDOMAINS})
    assert SOURCE_SPECS['haveibeenpwned'].routes == frozenset({ResultRoute.BREACHES})
    assert SOURCE_SPECS['hibpverified'].routes == frozenset({ResultRoute.EMAILS, ResultRoute.BREACHES})
    assert SOURCE_SPECS['leaklookup'].routes == frozenset({ResultRoute.EMAILS, ResultRoute.BREACHES})
    assert SOURCE_SPECS['urlscan'].routes == frozenset(
        {
            ResultRoute.SUBDOMAINS,
            ResultRoute.IPS,
            ResultRoute.ASNS,
            ResultRoute.URLS,
        }
    )


def test_every_url_source_uses_one_route() -> None:
    url_sources = {'apis-guru', 'bevigil', 'builtwith', 'gitlab', 'intelx', 'rocketreach', 'urlscan', 'zoomeye'}

    assert {spec.name for spec in SOURCE_SPECS.values() if ResultRoute.URLS in spec.routes} == url_sources
    assert {route.name for route in ResultRoute} == {
        'SUBDOMAINS',
        'EMAILS',
        'IPS',
        'ASNS',
        'PEOPLE',
        'URLS',
        'BREACHES',
    }


def test_every_url_adapter_uses_one_getter() -> None:
    adapters = (
        apisguru.SearchApisGuru,
        bevigil.SearchBeVigil,
        builtwith.SearchBuiltWith,
        gitlabsearch.SearchGitlab,
        intelxsearch.SearchIntelx,
        rocketreach.SearchRocketReach,
        urlscan.SearchUrlscan,
        zoomeyesearch.SearchZoomEye,
    )

    assert all(hasattr(adapter, 'get_urls') for adapter in adapters)
    assert not any(hasattr(adapter, 'get_links') for adapter in adapters)
    assert not any(hasattr(adapter, 'get_interestingurls') for adapter in adapters)
    assert not any(hasattr(adapter, 'get_interesting_urls') for adapter in adapters)


def test_rapiddns_declares_separate_subdomain_and_ip_routes() -> None:
    assert SOURCE_SPECS['rapiddns'].routes == frozenset({ResultRoute.SUBDOMAINS, ResultRoute.IPS})


def test_pentesttools_declares_its_normalized_subdomain_and_ip_routes() -> None:
    assert SOURCE_SPECS['pentesttools'].routes == frozenset({ResultRoute.SUBDOMAINS, ResultRoute.IPS})


def test_dehashed_declares_its_normalized_email_and_ip_routes() -> None:
    assert SOURCE_SPECS['dehashed'].routes == frozenset({ResultRoute.EMAILS, ResultRoute.IPS})


def test_leakix_declares_only_its_documented_subdomain_route() -> None:
    assert SOURCE_SPECS['leakix'].routes == frozenset({ResultRoute.SUBDOMAINS})


def test_unavailable_venacus_source_is_not_selectable() -> None:
    assert 'venacus' not in Core.get_supportedengines()
    assert 'venacus' not in SOURCE_SPECS
    assert 'venacus' not in _scheduled_source_names()


def test_source_lookup_preserves_case_insensitive_legacy_labels() -> None:
    assert get_source_spec('CRTsh') is SOURCE_SPECS['crtsh']


def test_crt_name_is_a_separate_passive_hostname_source() -> None:
    spec = get_source_spec('CRT-NAME')

    assert spec is SOURCE_SPECS['crt-name']
    assert spec.routes == frozenset({ResultRoute.SUBDOMAINS})
    assert spec.activity is ActivityClass.PASSIVE
