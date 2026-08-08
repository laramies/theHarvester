import sys

import pytest

from theHarvester import restfulHarvest


def test_help_does_not_offer_rate_limit_configuration(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['restfulHarvest', '--help'])

    with pytest.raises(SystemExit) as exit_info:
        restfulHarvest.main()

    assert exit_info.value.code == 0
    assert '--rate-limit' not in capsys.readouterr().out
