from dataclasses import dataclass
from enum import Enum, auto


class ResultRoute(Enum):
    """Normalized result collections a source can contribute.

    ``SUBDOMAINS`` contains in-scope descendant names reported by a source. It
    does not imply DNS resolution or current addressability. Legacy adapters
    and output formats may still call these values hosts for compatibility.
    """

    SUBDOMAINS = auto()
    EMAILS = auto()
    IPS = auto()
    ASNS = auto()
    PEOPLE = auto()
    LINKS = auto()
    INTERESTING_URLS = auto()
    BREACHES = auto()


_ROUTE_CAPABILITIES = {
    ResultRoute.SUBDOMAINS: 'subdomains',
    ResultRoute.EMAILS: 'emails',
    ResultRoute.IPS: 'ips',
    ResultRoute.ASNS: 'asns',
    ResultRoute.PEOPLE: 'people',
    ResultRoute.LINKS: 'urls',
    ResultRoute.INTERESTING_URLS: 'urls',
    ResultRoute.BREACHES: 'breaches',
}


@dataclass(frozen=True)
class SourceSpec:
    name: str
    routes: frozenset[ResultRoute]

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(_ROUTE_CAPABILITIES[route] for route in self.routes)


def _spec(name: str, *routes: ResultRoute) -> SourceSpec:
    return SourceSpec(
        name=name,
        routes=frozenset(routes),
    )


_SPECS = (
    _spec('baidu', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('bevigil', ResultRoute.SUBDOMAINS, ResultRoute.INTERESTING_URLS),
    _spec('brave', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('bufferoverun', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('builtwith', ResultRoute.SUBDOMAINS, ResultRoute.INTERESTING_URLS),
    _spec('censys', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('certspotter', ResultRoute.SUBDOMAINS),
    _spec('chaos', ResultRoute.SUBDOMAINS),
    _spec('commoncrawl', ResultRoute.SUBDOMAINS),
    _spec('criminalip', ResultRoute.SUBDOMAINS, ResultRoute.IPS, ResultRoute.ASNS),
    _spec('crtsh', ResultRoute.SUBDOMAINS),
    _spec('dehashed', ResultRoute.IPS),
    _spec('dnsdb', ResultRoute.SUBDOMAINS),
    _spec('dnsdumpster', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('duckduckgo', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('dymo', ResultRoute.SUBDOMAINS),
    _spec('fofa', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('fullhunt', ResultRoute.SUBDOMAINS),
    _spec('github-code', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('gitlab', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('hackertarget', ResultRoute.SUBDOMAINS),
    _spec('haveibeenpwned', ResultRoute.BREACHES),
    _spec('hibpverified', ResultRoute.EMAILS, ResultRoute.BREACHES),
    _spec('hudsonrock', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('hunter', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('hunterhow', ResultRoute.SUBDOMAINS),
    _spec('intelx', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.INTERESTING_URLS),
    _spec('leakix', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('leaklookup', ResultRoute.EMAILS),
    _spec('mojeek', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('netlas', ResultRoute.SUBDOMAINS),
    _spec('onyphe', ResultRoute.SUBDOMAINS, ResultRoute.IPS, ResultRoute.ASNS),
    _spec('otx', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('pentesttools', ResultRoute.SUBDOMAINS),
    _spec('projectdiscovery', ResultRoute.SUBDOMAINS),
    _spec('rapiddns', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('robtex', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('rocketreach', ResultRoute.EMAILS, ResultRoute.LINKS),
    _spec('securityTrails', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('securityscorecard', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('sherlockeye', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('shodan', ResultRoute.SUBDOMAINS),
    _spec('shodanInternetDB', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('shodanct', ResultRoute.SUBDOMAINS),
    _spec('subdomaincenter', ResultRoute.SUBDOMAINS),
    _spec('subdomainfinderc99', ResultRoute.SUBDOMAINS),
    _spec('thc', ResultRoute.SUBDOMAINS),
    _spec('tomba', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('urlscan', ResultRoute.SUBDOMAINS, ResultRoute.IPS, ResultRoute.ASNS, ResultRoute.INTERESTING_URLS),
    _spec('venacus', ResultRoute.EMAILS, ResultRoute.IPS, ResultRoute.PEOPLE, ResultRoute.INTERESTING_URLS),
    _spec('virustotal', ResultRoute.SUBDOMAINS),
    _spec('waybackarchive', ResultRoute.SUBDOMAINS),
    _spec('whoisxml', ResultRoute.SUBDOMAINS),
    _spec('windvane', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('yahoo', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec(
        'zoomeye',
        ResultRoute.SUBDOMAINS,
        ResultRoute.EMAILS,
        ResultRoute.IPS,
        ResultRoute.ASNS,
        ResultRoute.INTERESTING_URLS,
    ),
)

SOURCE_SPECS = {spec.name: spec for spec in _SPECS}
_CASEFOLDED_SOURCE_SPECS = {name.casefold(): spec for name, spec in SOURCE_SPECS.items()}


def get_source_spec(name: str) -> SourceSpec:
    return _CASEFOLDED_SOURCE_SPECS[name.casefold()]
