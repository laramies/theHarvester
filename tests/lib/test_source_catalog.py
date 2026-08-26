from theHarvester.discovery import apisguru, bevigil, builtwith, gitlabsearch, intelxsearch, rocketreach, urlscan, zoomeyesearch
from theHarvester.lib.source_catalog import SOURCE_SPECS, ActivityClass, ResultRoute, SourceSpec, get_source_spec, resolve_sources


def test_dead_threatcrowd_source_is_not_selectable() -> None:
    assert 'threatcrowd' not in SOURCE_SPECS


def test_invalid_bitbucket_domain_source_is_not_selectable() -> None:
    assert 'bitbucket' not in SOURCE_SPECS


def test_projectdiscovery_is_the_only_selector_for_the_chaos_corpus() -> None:
    selected = [spec.name for spec in SOURCE_SPECS.values() if spec.activity is ActivityClass.PASSIVE]

    assert 'projectdiscovery' in selected
    assert 'chaos' not in selected


def test_removed_inert_sources_are_not_supported() -> None:
    removed = {'linkedin', 'netcraft', 'omnisint', 'sublist3r', 'zoomeyeapi'}

    assert not removed & set(SOURCE_SPECS)


def test_subdomain_route_drives_subdomain_capability() -> None:
    spec = SourceSpec(
        name='example',
        routes=frozenset({ResultRoute.SUBDOMAINS, ResultRoute.URLS}),
    )

    assert spec.capabilities == frozenset({'subdomains', 'urls'})


def test_source_specs_describe_consolidated_routes_not_getter_presence() -> None:
    assert SOURCE_SPECS['apis-guru'].routes == frozenset({ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.URLS})
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


def test_catalog_declares_sources_that_retain_provider_hostname_evidence_without_dns_confirmation() -> None:
    assert {spec.name for spec in SOURCE_SPECS.values() if spec.retains_unresolved_hostnames} == {
        'hackertarget',
        'pentesttools',
        'rapiddns',
    }


def test_pentesttools_declares_its_normalized_subdomain_and_ip_routes() -> None:
    assert SOURCE_SPECS['pentesttools'].routes == frozenset({ResultRoute.SUBDOMAINS, ResultRoute.IPS})


def test_dehashed_declares_its_normalized_email_and_ip_routes() -> None:
    assert SOURCE_SPECS['dehashed'].routes == frozenset({ResultRoute.EMAILS, ResultRoute.IPS})


def test_leakix_declares_only_its_documented_subdomain_route() -> None:
    assert SOURCE_SPECS['leakix'].routes == frozenset({ResultRoute.SUBDOMAINS})


def test_unavailable_venacus_source_is_not_selectable() -> None:
    assert 'venacus' not in SOURCE_SPECS


def test_source_lookup_preserves_case_insensitive_legacy_labels() -> None:
    assert get_source_spec('CRTsh') is SOURCE_SPECS['crtsh']


def test_source_selection_canonicalizes_case_insensitive_legacy_labels() -> None:
    assert resolve_sources('CRTsh,ShodanInternetDB') == ['crtsh', 'shodanInternetDB']


def test_crt_name_is_a_separate_passive_hostname_source() -> None:
    spec = get_source_spec('CRT-NAME')

    assert spec is SOURCE_SPECS['crt-name']
    assert spec.routes == frozenset({ResultRoute.SUBDOMAINS})
    assert spec.activity is ActivityClass.PASSIVE
