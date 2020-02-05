import os
import sys
from unittest.mock import patch, MagicMock
import theHarvester.__main__ as harvester
import pytest

domain = 'metasploit.com'
sys.argv = args = [os.path.curdir + 'theHarvester.py', '-d', domain, '-b', 'domain']


@pytest.mark.asyncio
@patch('theHarvester.discovery.baidusearch.SearchBaidu')
@patch('theHarvester.lib.stash.StashManager')
async def test_baidu(stash, search_engine):
    args[-1] = 'baidu'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.bingsearch.SearchBing')
@patch('theHarvester.lib.stash.StashManager')
async def test_bing(stash, search_engine):
    args[-1] = 'bing'
    await harvester.start()
    args[-1] = 'bingapi'
    await harvester.start()
    assert stash().store_all.call_count == 4


@pytest.mark.asyncio
@patch('theHarvester.discovery.certspottersearch.SearchCertspoter')
@patch('theHarvester.lib.stash.StashManager')
async def test_certspotter(stash, search_engine):
    args[-1] = 'certspotter'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.crtsh.SearchCrtsh')
@patch('theHarvester.lib.stash.StashManager')
async def test_crtsh(stash, search_engine):
    args[-1] = 'crtsh'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.dnsdumpster.SearchDnsDumpster')
@patch('theHarvester.lib.stash.StashManager')
async def test_dnsdumpster(stash, search_engine):
    args[-1] = 'dnsdumpster'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.dogpilesearch.SearchDogpile')
@patch('theHarvester.lib.stash.StashManager')
async def test_dogpile(stash, search_engine):
    args[-1] = 'dogpile'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.duckduckgosearch.SearchDuckDuckGo')
@patch('theHarvester.lib.stash.StashManager')
async def test_duckduckgo(stash, search_engine):
    args[-1] = 'duckduckgo'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.githubcode.SearchGithubCode')
@patch('theHarvester.lib.stash.StashManager')
async def test_github(stash, search_engine):
    args[-1] = 'github-code'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.exaleadsearch.SearchExalead')
@patch('theHarvester.lib.stash.StashManager')
async def test_exalead(stash, search_engine):
    args[-1] = 'exalead'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.googlesearch.SearchGoogle')
@patch('theHarvester.lib.stash.StashManager')
async def test_google(stash, search_engine):
    args[-1] = 'google'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.huntersearch.SearchHunter')
@patch('theHarvester.lib.stash.StashManager')
async def test_hunter(stash, search_engine):
    args[-1] = 'hunter'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.intelxsearch.SearchIntelx')
@patch('theHarvester.lib.stash.StashManager')
async def test_intelx(stash, search_engine):
    args[-1] = 'intelx'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.linkedinsearch.SearchLinkedin')
@patch('theHarvester.lib.stash.StashManager')
async def test_linkedin(stash, search_engine):
    args[-1] = 'linkedin'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.linkedinsearch.SearchLinkedin')
@patch('theHarvester.lib.stash.StashManager')
async def test_linkedin_links(stash, search_engine):
    args[-1] = 'linkedin_links'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.netcraft.SearchNetcraft')
@patch('theHarvester.lib.stash.StashManager')
async def test_netcraft(stash, search_engine):
    args[-1] = 'netcraft'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.otxsearch.SearchOtx')
@patch('theHarvester.lib.stash.StashManager')
async def test_otx(stash, search_engine):
    args[-1] = 'otx'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.securitytrailssearch.SearchSecuritytrail')
@patch('theHarvester.lib.stash.StashManager')
async def test_security_trails(stash, search_engine):
    args[-1] = 'securityTrails'
    await harvester.start()
    assert stash().store_all.call_count == 2


@pytest.mark.asyncio
@patch('theHarvester.discovery.suip.SearchSuip')
@patch('theHarvester.lib.stash.StashManager')
async def test_suip(stash, search_engine):
    args[-1] = 'suip'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.threatcrowd.SearchThreatcrowd')
@patch('theHarvester.lib.stash.StashManager')
async def test_threatcrowd(stash, search_engine):
    args[-1] = 'threatcrowd'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.trello.SearchTrello')
@patch('theHarvester.lib.stash.StashManager')
async def test_trello(stash, search_engine):
    search_engine().get_results = MagicMock(return_value=('user@trello.com', 'trello', 'trello.com'))
    args[-1] = 'trello'
    await harvester.start()
    assert stash().store_all.call_count == 3


@pytest.mark.asyncio
@patch('theHarvester.discovery.twittersearch.SearchTwitter')
@patch('theHarvester.lib.stash.StashManager')
async def test_twitter(stash, search_engine):
    args[-1] = 'twitter'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.virustotal.SearchVirustotal')
@patch('theHarvester.lib.stash.StashManager')
async def test_virustotal(stash, search_engine):
    args[-1] = 'virustotal'
    await harvester.start()
    assert stash().store_all.call_count == 1


@pytest.mark.asyncio
@patch('theHarvester.discovery.yahoosearch.SearchYahoo')
@patch('theHarvester.lib.stash.StashManager')
async def test_yahoo(stash, search_engine):
    args[-1] = 'yahoo'
    await harvester.start()
    assert stash().store_all.call_count == 2
