import ast
import asyncio
import sys
from collections.abc import Callable, Coroutine
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from theHarvester import theHarvester

LoopFactory = Callable[[], asyncio.AbstractEventLoop]


def _capture_loop_factory(monkeypatch: pytest.MonkeyPatch) -> list[LoopFactory | None]:
    observed: list[LoopFactory | None] = []

    def run(coroutine: Coroutine[Any, Any, None], *, loop_factory: LoopFactory | None = None) -> None:
        coroutine.close()
        observed.append(loop_factory)

    monkeypatch.setattr(theHarvester.asyncio, 'run', run)
    return observed


@pytest.mark.parametrize(('platform', 'module_name'), [('darwin', 'uvloop'), ('win32', 'winloop')])
def test_cli_uses_platform_loop_factory_when_available(monkeypatch: pytest.MonkeyPatch, platform: str, module_name: str) -> None:
    optional_loop = ModuleType(module_name)

    def new_event_loop() -> asyncio.AbstractEventLoop:
        raise AssertionError('factory should be passed to asyncio.run, not called by the bootstrap')

    optional_loop.new_event_loop = new_event_loop  # type: ignore[attr-defined]
    observed = _capture_loop_factory(monkeypatch)
    monkeypatch.setattr(sys, 'platform', platform)
    monkeypatch.setitem(sys.modules, module_name, optional_loop)

    theHarvester.main()

    assert observed == [new_event_loop]


@pytest.mark.parametrize(('platform', 'module_name'), [('linux', 'uvloop'), ('win32', 'winloop')])
def test_cli_uses_standard_loop_when_optional_loop_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, platform: str, module_name: str
) -> None:
    observed = _capture_loop_factory(monkeypatch)
    monkeypatch.setattr(sys, 'platform', platform)
    monkeypatch.setitem(sys.modules, module_name, None)

    theHarvester.main()

    assert observed == [None]


def test_coroutines_do_not_request_an_ambient_event_loop() -> None:
    violations: list[str] = []
    for path in Path('theHarvester').rglob('*.py'):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == 'asyncio'
                and node.func.attr == 'get_event_loop'
            ):
                violations.append(f'{path}:{node.lineno}')

    assert violations == []


def test_cli_bootstrap_owns_one_local_run_boundary_without_global_mutation() -> None:
    source = Path('theHarvester/theHarvester.py').read_text(encoding='utf-8')
    tree = ast.parse(source)
    run_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == 'asyncio'
        and node.func.attr == 'run'
    ]

    assert len(run_calls) == 1
    assert [keyword.arg for keyword in run_calls[0].keywords] == ['loop_factory']
    for obsolete in (
        'DefaultEventLoopPolicy',
        'set_event_loop_policy',
        '.install(',
        'multiprocessing',
        'aiomultiprocess',
        'set_context(',
        'freeze_support(',
    ):
        assert obsolete not in source
