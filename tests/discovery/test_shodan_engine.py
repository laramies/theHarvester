import socket
import sys
from collections import OrderedDict

import pytest


class TestShodanEngine:
    @pytest.mark.asyncio
    async def test_shodan_engine_processes_without_work_item_error_and_yields_hostnames(self, monkeypatch, capsys):
        # Import inside the test so monkeypatching affects the already-imported module namespace.
        import theHarvester.__main__ as main_module

        # Make DNS resolution deterministic and offline.
        monkeypatch.setattr(socket, "gethostbyname", lambda _domain: "1.2.3.4", raising=True)

        # Avoid filesystem/sqlite side effects.
        class DummyStashManager:
            async def do_init(self) -> None:
                return None

            async def store_all(self, domain, all, res_type, source) -> None:  # noqa: A002
                return None

        monkeypatch.setattr(main_module.stash, "StashManager", DummyStashManager, raising=True)

        # Stub Shodan search to avoid network and API key requirements.
        class DummySearchShodan:
            async def search_ip(self, ip):
                return OrderedDict({ip: {"hostnames": ["a.example.com", "b.example.com"]}})

        monkeypatch.setattr(main_module.shodansearch, "SearchShodan", DummySearchShodan, raising=True)

        # Run the CLI path that uses the engine queue/worker (`-b shodan`).
        monkeypatch.setattr(sys, "argv", ["theHarvester", "-d", "example.com", "-b", "shodan"], raising=True)

        with pytest.raises(SystemExit) as excinfo:
            await main_module.start()
        assert excinfo.value.code == 0

        out = capsys.readouterr().out
        assert 'A error occurred while processing a "work item"' not in out
        assert "a.example.com" in out
        assert "b.example.com" in out
