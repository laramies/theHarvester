import os
import sys
from unittest.mock import patch

import theHarvester.__main__ as theHarvester

domain = 'metasploit.com'
sys.argv = args = [os.path.curdir + 'theHarvester.py', '-d', domain, '-b', 'domain']


@patch('theHarvester.discovery.certspottersearch.SearchCertspoter')
@patch('theHarvester.lib.stash.stash_manager')
def test_certspotter(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'certspotter'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.crtsh.SearchCrtsh')
@patch('theHarvester.lib.stash.stash_manager')
def test_crtsh(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'crtsh'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.dnsdumpster.SearchDnsDumpster')
@patch('theHarvester.lib.stash.stash_manager')
def test_dnsdumpster(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'dnsdumpster'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.dogpilesearch.SearchDogpile')
@patch('theHarvester.lib.stash.stash_manager')
def test_dogpile(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'dogpile'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 2


@patch('theHarvester.discovery.duckduckgosearch.SearchDuckDuckGo')
@patch('theHarvester.lib.stash.stash_manager')
def test_duckduckgo(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'duckduckgo'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 2


@patch('theHarvester.discovery.exaleadsearch.SearchExalead')
@patch('theHarvester.lib.stash.stash_manager')
def test_exalead(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'exalead'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 2


@patch('theHarvester.discovery.googlesearch.SearchGoogle')
@patch('theHarvester.lib.stash.stash_manager')
def test_google(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'google'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 2


@patch('theHarvester.discovery.linkedinsearch.SearchLinkedin')
@patch('theHarvester.lib.stash.stash_manager')
def test_linkedin(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'linkedin'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.linkedinsearch.SearchLinkedin')
@patch('theHarvester.lib.stash.stash_manager')
def test_linkedin_links(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'linkedin_links'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.netcraft.SearchNetcraft')
@patch('theHarvester.lib.stash.stash_manager')
def test_netcraft(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'netcraft'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.otxsearch.SearchOtx')
@patch('theHarvester.lib.stash.stash_manager')
def test_otx(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'otx'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 2


@patch('theHarvester.discovery.securitytrailssearch.SearchSecuritytrail')
@patch('theHarvester.lib.stash.stash_manager')
def test_security_trails(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'securityTrails'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 2


@patch('theHarvester.discovery.suip.SearchSuip')
@patch('theHarvester.lib.stash.stash_manager')
def test_suip(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'suip'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.threatcrowd.SearchThreatcrowd')
@patch('theHarvester.lib.stash.stash_manager')
def test_threatcrowd(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'threatcrowd'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.twittersearch.SearchTwitter')
@patch('theHarvester.lib.stash.stash_manager')
def test_twitter(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'twitter'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.virustotal.SearchVirustotal')
@patch('theHarvester.lib.stash.stash_manager')
def test_virustotal(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'virustotal'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 1


@patch('theHarvester.discovery.yahoosearch.SearchYahoo')
@patch('theHarvester.lib.stash.stash_manager')
def test_yahoo(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'yahoo'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 2
