import os
import sys
from unittest.mock import patch, MagicMock

import theHarvester.__main__ as harvester

domain = 'metasploit.com'
sys.argv = args = [os.path.curdir + 'theHarvester.py', '-d', domain, '-b', 'domain']


@patch('theHarvester.discovery.baidusearch.SearchBaidu')
@patch('theHarvester.lib.stash.StashManager')
def test_baidu(stash, search_engine):
    args[-1] = 'baidu'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.bingsearch.SearchBing')
@patch('theHarvester.lib.stash.StashManager')
def test_bing(stash, search_engine):
    args[-1] = 'bing'
    harvester.start()
    args[-1] = 'bingapi'
    harvester.start()
    assert stash().store_all.call_count == 4


@patch('theHarvester.discovery.certspottersearch.SearchCertspoter')
@patch('theHarvester.lib.stash.StashManager')
def test_certspotter(stash, search_engine):
    args[-1] = 'certspotter'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.crtsh.SearchCrtsh')
@patch('theHarvester.lib.stash.StashManager')
def test_crtsh(stash, search_engine):
    args[-1] = 'crtsh'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.dnsdumpster.SearchDnsDumpster')
@patch('theHarvester.lib.stash.StashManager')
def test_dnsdumpster(stash, search_engine):
    args[-1] = 'dnsdumpster'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.dogpilesearch.SearchDogpile')
@patch('theHarvester.lib.stash.StashManager')
def test_dogpile(stash, search_engine):
    args[-1] = 'dogpile'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.duckduckgosearch.SearchDuckDuckGo')
@patch('theHarvester.lib.stash.StashManager')
def test_duckduckgo(stash, search_engine):
    args[-1] = 'duckduckgo'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.githubcode.SearchGithubCode')
@patch('theHarvester.lib.stash.StashManager')
def test_github(stash, search_engine):
    args[-1] = 'github-code'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.exaleadsearch.SearchExalead')
@patch('theHarvester.lib.stash.StashManager')
def test_exalead(stash, search_engine):
    args[-1] = 'exalead'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.googlesearch.SearchGoogle')
@patch('theHarvester.lib.stash.StashManager')
def test_google(stash, search_engine):
    args[-1] = 'google'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.huntersearch.SearchHunter')
@patch('theHarvester.lib.stash.StashManager')
def test_hunter(stash, search_engine):
    args[-1] = 'hunter'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.intelxsearch.SearchIntelx')
@patch('theHarvester.lib.stash.StashManager')
def test_intelx(stash, search_engine):
    args[-1] = 'intelx'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.linkedinsearch.SearchLinkedin')
@patch('theHarvester.lib.stash.StashManager')
def test_linkedin(stash, search_engine):
    args[-1] = 'linkedin'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.linkedinsearch.SearchLinkedin')
@patch('theHarvester.lib.stash.StashManager')
def test_linkedin_links(stash, search_engine):
    args[-1] = 'linkedin_links'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.netcraft.SearchNetcraft')
@patch('theHarvester.lib.stash.StashManager')
def test_netcraft(stash, search_engine):
    args[-1] = 'netcraft'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.otxsearch.SearchOtx')
@patch('theHarvester.lib.stash.StashManager')
def test_otx(stash, search_engine):
    args[-1] = 'otx'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.securitytrailssearch.SearchSecuritytrail')
@patch('theHarvester.lib.stash.StashManager')
def test_security_trails(stash, search_engine):
    args[-1] = 'securityTrails'
    harvester.start()
    assert stash().store_all.call_count == 2


@patch('theHarvester.discovery.suip.SearchSuip')
@patch('theHarvester.lib.stash.StashManager')
def test_suip(stash, search_engine):
    args[-1] = 'suip'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.threatcrowd.SearchThreatcrowd')
@patch('theHarvester.lib.stash.StashManager')
def test_threatcrowd(stash, search_engine):
    args[-1] = 'threatcrowd'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.trello.SearchTrello')
@patch('theHarvester.lib.stash.StashManager')
def test_trello(stash, search_engine):
    search_engine().get_results = MagicMock(return_value=('user@trello.com', 'trello', 'trello.com'))
    args[-1] = 'trello'
    harvester.start()
    assert stash().store_all.call_count == 3


@patch('theHarvester.discovery.twittersearch.SearchTwitter')
@patch('theHarvester.lib.stash.StashManager')
def test_twitter(stash, search_engine):
    args[-1] = 'twitter'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.virustotal.SearchVirustotal')
@patch('theHarvester.lib.stash.StashManager')
def test_virustotal(stash, search_engine):
    args[-1] = 'virustotal'
    harvester.start()
    assert stash().store_all.call_count == 1


@patch('theHarvester.discovery.yahoosearch.SearchYahoo')
@patch('theHarvester.lib.stash.StashManager')
def test_yahoo(stash, search_engine):
    args[-1] = 'yahoo'
    harvester.start()
    assert stash().store_all.call_count == 2
