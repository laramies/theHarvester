from __future__ import annotations

import ipaddress
import socket
from typing import Any

import pytest

NETWORK_GUARD = pytest.StashKey[pytest.MonkeyPatch]()

_getaddrinfo = socket.getaddrinfo
_gethostbyaddr = socket.gethostbyaddr
_gethostbyname = socket.gethostbyname
_gethostbyname_ex = socket.gethostbyname_ex
_getnameinfo = socket.getnameinfo
_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex
_sendto = socket.socket.sendto

_ERROR = (
    'External networking through Python socket APIs is disabled in routine tests. '
    'Mock the boundary or mark the test with @pytest.mark.live_network and pass '
    '--run-live-network -m live_network.'
)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        '--run-live-network',
        action='store_true',
        default=False,
        help='run tests that contact external services',
    )


def pytest_sessionstart(session: pytest.Session) -> None:
    guard = pytest.MonkeyPatch()
    guard.setattr(socket, 'getaddrinfo', _guarded_getaddrinfo)
    guard.setattr(socket, 'gethostbyaddr', _guarded_gethostbyaddr)
    guard.setattr(socket, 'gethostbyname', _guarded_gethostbyname)
    guard.setattr(socket, 'gethostbyname_ex', _guarded_gethostbyname_ex)
    guard.setattr(socket, 'getnameinfo', _guarded_getnameinfo)
    guard.setattr(socket.socket, 'connect', _guarded_connect)
    guard.setattr(socket.socket, 'connect_ex', _guarded_connect_ex)
    guard.setattr(socket.socket, 'sendto', _guarded_sendto)
    session.config.stash[NETWORK_GUARD] = guard


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption('--run-live-network'):
        if config.getoption('markexpr') != 'live_network':
            raise pytest.UsageError('--run-live-network requires -m live_network')
        return

    skip_live = pytest.mark.skip(reason='requires --run-live-network -m live_network')
    for item in items:
        if item.get_closest_marker('live_network') is not None:
            item.add_marker(skip_live)


def pytest_collection_finish(session: pytest.Session) -> None:
    if session.config.getoption('--run-live-network'):
        _remove_network_guard(session.config)


def pytest_sessionfinish(session: pytest.Session) -> None:
    _remove_network_guard(session.config)


def _remove_network_guard(config: pytest.Config) -> None:
    guard = config.stash.get(NETWORK_GUARD, None)
    if guard is not None:
        guard.undo()
        del config.stash[NETWORK_GUARD]


def _is_loopback_host(host: object) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode(errors='ignore')
    if not isinstance(host, str):
        return False

    normalized = host.strip('[]').split('%', 1)[0].lower()
    if normalized in {'localhost', 'localhost.localdomain'}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_loopback_address(family: int, address: object) -> bool:
    if family == socket.AF_UNIX:
        return True
    return isinstance(address, tuple) and bool(address) and _is_loopback_host(address[0])


def _guarded_getaddrinfo(host: bytes | str | None, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
    if not _is_loopback_host(host):
        raise AssertionError(f'{_ERROR} Attempted host: {host!r}.')
    return _getaddrinfo(host, *args, **kwargs)


def _guarded_gethostbyaddr(host: str) -> tuple[str, list[str], list[str]]:
    if not _is_loopback_host(host):
        raise AssertionError(f'{_ERROR} Attempted host: {host!r}.')
    return _gethostbyaddr(host)


def _guarded_gethostbyname(host: str) -> str:
    if not _is_loopback_host(host):
        raise AssertionError(f'{_ERROR} Attempted host: {host!r}.')
    return _gethostbyname(host)


def _guarded_gethostbyname_ex(host: str) -> tuple[str, list[str], list[str]]:
    if not _is_loopback_host(host):
        raise AssertionError(f'{_ERROR} Attempted host: {host!r}.')
    return _gethostbyname_ex(host)


def _guarded_getnameinfo(address: tuple[Any, ...], flags: int) -> tuple[str, str]:
    if not address or not _is_loopback_host(address[0]):
        raise AssertionError(f'{_ERROR} Attempted address: {address!r}.')
    return _getnameinfo(address, flags)


def _guarded_connect(sock: socket.socket, address: object) -> None:
    if not _is_loopback_address(sock.family, address):
        raise AssertionError(f'{_ERROR} Attempted address: {address!r}.')
    _connect(sock, address)  # type: ignore[arg-type]


def _guarded_connect_ex(sock: socket.socket, address: object) -> int:
    if not _is_loopback_address(sock.family, address):
        raise AssertionError(f'{_ERROR} Attempted address: {address!r}.')
    return _connect_ex(sock, address)  # type: ignore[arg-type]


def _guarded_sendto(sock: socket.socket, data: bytes, *args: Any) -> int:
    address = args[-1] if args else None
    if not _is_loopback_address(sock.family, address):
        raise AssertionError(f'{_ERROR} Attempted address: {address!r}.')
    return _sendto(sock, data, *args)
