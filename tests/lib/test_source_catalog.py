import ast
from pathlib import Path

from theHarvester.lib.core import Core
from theHarvester.lib.source_catalog import SOURCE_SPECS, ResultRoute, SourceSpec, get_source_spec


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
        routes=frozenset(
            {
                ResultRoute.SUBDOMAINS,
                ResultRoute.LINKS,
                ResultRoute.INTERESTING_URLS,
            }
        ),
    )

    assert spec.capabilities == frozenset({'subdomains', 'urls'})


def test_source_specs_describe_consolidated_routes_not_getter_presence() -> None:
    assert SOURCE_SPECS['gitlab'].routes == frozenset(
        {ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.URLS}
    )
    assert SOURCE_SPECS['haveibeenpwned'].routes == frozenset({ResultRoute.BREACHES})
    assert SOURCE_SPECS['hibpverified'].routes == frozenset({ResultRoute.EMAILS, ResultRoute.BREACHES})
    assert SOURCE_SPECS['leaklookup'].routes == frozenset({ResultRoute.EMAILS, ResultRoute.BREACHES})
    assert SOURCE_SPECS['urlscan'].routes == frozenset(
        {
            ResultRoute.SUBDOMAINS,
            ResultRoute.IPS,
            ResultRoute.ASNS,
            ResultRoute.INTERESTING_URLS,
        }
    )


def test_rapiddns_declares_separate_subdomain_and_ip_routes() -> None:
    assert SOURCE_SPECS['rapiddns'].routes == frozenset({ResultRoute.SUBDOMAINS, ResultRoute.IPS})


def test_pentesttools_declares_its_normalized_subdomain_and_ip_routes() -> None:
    assert SOURCE_SPECS['pentesttools'].routes == frozenset({ResultRoute.SUBDOMAINS, ResultRoute.IPS})


def test_unavailable_venacus_source_is_not_selectable() -> None:
    assert 'venacus' not in Core.get_supportedengines()
    assert 'venacus' not in SOURCE_SPECS
    assert 'venacus' not in _scheduled_source_names()


def test_source_lookup_preserves_case_insensitive_legacy_labels() -> None:
    assert get_source_spec('CRTsh') is SOURCE_SPECS['crtsh']
