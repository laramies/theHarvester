import os
import sys
from unittest.mock import patch

import theHarvester.__main__ as theHarvester

domain = 'metasploit.com'
sys.argv = args = [os.path.curdir + 'theHarvester.py', '-d', domain, '-b', 'domain']


@patch('theHarvester.discovery.baidusearch.SearchBaidu')
@patch('theHarvester.lib.stash.stash_manager')
def test_baidu(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'baidu'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 2


@patch('theHarvester.discovery.crtsh.SearchCrtsh')
@patch('theHarvester.lib.stash.stash_manager')
def test_certsh(stash, search_engine):
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
def test_dogpilesearch(stash, search_engine):
    mock_stash = stash()
    args[-1] = 'dogpile'
    theHarvester.start()
    assert mock_stash.store_all.call_count == 2
