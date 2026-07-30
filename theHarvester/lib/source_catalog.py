from dataclasses import dataclass
from enum import Enum, auto


class ResultRoute(Enum):
    HOSTS = auto()
    EMAILS = auto()
    IPS = auto()
    ASNS = auto()
    PEOPLE = auto()
    LINKS = auto()
    INTERESTING_URLS = auto()


_ROUTE_CAPABILITIES = {
    ResultRoute.HOSTS: 'subdomains',
    ResultRoute.EMAILS: 'emails',
    ResultRoute.IPS: 'ips',
    ResultRoute.ASNS: 'asns',
    ResultRoute.PEOPLE: 'people',
    ResultRoute.LINKS: 'urls',
    ResultRoute.INTERESTING_URLS: 'urls',
}


@dataclass(frozen=True)
class SourceSpec:
    name: str
    routes: frozenset[ResultRoute]
    queries_provider_descendants: bool = False

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(_ROUTE_CAPABILITIES[route] for route in self.routes)


def _spec(name: str, *routes: ResultRoute, queries_provider_descendants: bool = False) -> SourceSpec:
    return SourceSpec(
        name=name,
        routes=frozenset(routes),
        queries_provider_descendants=queries_provider_descendants,
    )


_SPECS = (
    _spec('baidu', ResultRoute.HOSTS, ResultRoute.EMAILS, queries_provider_descendants=True),
    _spec('bevigil', ResultRoute.HOSTS, ResultRoute.INTERESTING_URLS, queries_provider_descendants=True),
    _spec('bitbucket', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('brave', ResultRoute.HOSTS, ResultRoute.EMAILS, queries_provider_descendants=True),
    _spec('bufferoverun', ResultRoute.HOSTS, ResultRoute.IPS, queries_provider_descendants=True),
    _spec('builtwith', ResultRoute.HOSTS, ResultRoute.INTERESTING_URLS),
    _spec('censys', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('certspotter', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('chaos', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('commoncrawl', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('criminalip', ResultRoute.HOSTS, ResultRoute.IPS, ResultRoute.ASNS, queries_provider_descendants=True),
    _spec('crtsh', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('dehashed', ResultRoute.IPS),
    _spec('dnsdb', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('dnsdumpster', ResultRoute.HOSTS, ResultRoute.IPS, queries_provider_descendants=True),
    _spec('duckduckgo', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('dymo', ResultRoute.HOSTS),
    _spec('fofa', ResultRoute.HOSTS, ResultRoute.IPS, queries_provider_descendants=True),
    _spec('fullhunt', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('github-code', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('gitlab', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('hackertarget', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('haveibeenpwned'),
    _spec('hudsonrock', ResultRoute.HOSTS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('hunter', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('hunterhow', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('intelx', ResultRoute.HOSTS, ResultRoute.EMAILS, ResultRoute.INTERESTING_URLS),
    _spec('leakix', ResultRoute.HOSTS, ResultRoute.EMAILS, queries_provider_descendants=True),
    _spec('leaklookup', ResultRoute.EMAILS),
    _spec('mojeek', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('netlas', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('onyphe', ResultRoute.HOSTS, ResultRoute.IPS, ResultRoute.ASNS),
    _spec('otx', ResultRoute.HOSTS, ResultRoute.IPS, queries_provider_descendants=True),
    _spec('pentesttools', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('projectdiscovery', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('rapiddns', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('robtex', ResultRoute.HOSTS, ResultRoute.IPS, queries_provider_descendants=True),
    _spec('rocketreach', ResultRoute.EMAILS, ResultRoute.LINKS),
    _spec('securityTrails', ResultRoute.HOSTS, ResultRoute.IPS, queries_provider_descendants=True),
    _spec('securityscorecard', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('sherlockeye', ResultRoute.HOSTS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('shodan', ResultRoute.HOSTS),
    _spec('shodanInternetDB', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('subdomaincenter', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('subdomainfinderc99', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('thc', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('threatcrowd', ResultRoute.HOSTS, ResultRoute.IPS, queries_provider_descendants=True),
    _spec('tomba', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec(
        'urlscan',
        ResultRoute.HOSTS,
        ResultRoute.IPS,
        ResultRoute.ASNS,
        ResultRoute.INTERESTING_URLS,
        queries_provider_descendants=True,
    ),
    _spec('venacus', ResultRoute.EMAILS, ResultRoute.IPS, ResultRoute.PEOPLE, ResultRoute.INTERESTING_URLS),
    _spec('virustotal', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('waybackarchive', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('whoisxml', ResultRoute.HOSTS, queries_provider_descendants=True),
    _spec('windvane', ResultRoute.HOSTS, ResultRoute.EMAILS, ResultRoute.IPS, queries_provider_descendants=True),
    _spec('yahoo', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec(
        'zoomeye',
        ResultRoute.HOSTS,
        ResultRoute.EMAILS,
        ResultRoute.IPS,
        ResultRoute.ASNS,
        ResultRoute.INTERESTING_URLS,
        queries_provider_descendants=True,
    ),
)

SOURCE_SPECS = {spec.name: spec for spec in _SPECS}
_CASEFOLDED_SOURCE_SPECS = {name.casefold(): spec for name, spec in SOURCE_SPECS.items()}


def get_source_spec(name: str) -> SourceSpec:
    return _CASEFOLDED_SOURCE_SPECS[name.casefold()]
