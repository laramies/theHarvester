from __future__ import annotations

import socket
from contextlib import suppress
from typing import TYPE_CHECKING

import httpx
import pytest

if TYPE_CHECKING:
    from pathlib import Path


def test_python_socket_network_is_blocked_by_default() -> None:
    with pytest.raises(AssertionError, match='External networking through Python socket APIs is disabled'):
        socket.getaddrinfo('example.com', 443)
    with pytest.raises(AssertionError, match='External networking through Python socket APIs is disabled'):
        socket.gethostbyname('example.com')
    with (
        socket.socket() as tcp_socket,
        pytest.raises(AssertionError, match='External networking through Python socket APIs is disabled'),
    ):
        tcp_socket.connect_ex(('192.0.2.1', 443))
    with (
        socket.socket(type=socket.SOCK_DGRAM) as udp_socket,
        pytest.raises(AssertionError, match='External networking through Python socket APIs is disabled'),
    ):
        udp_socket.sendto(b'test', ('192.0.2.1', 53))


def test_http_client_cannot_escape_network_guard() -> None:
    with pytest.raises(AssertionError, match='External networking through Python socket APIs is disabled'):
        httpx.get('https://example.com', trust_env=False)


def test_loopback_network_remains_available(tmp_path: Path) -> None:
    addresses = socket.getaddrinfo('localhost', 0)
    ipv6_addresses = socket.getaddrinfo('::1', 0)
    assert addresses
    assert ipv6_addresses

    with socket.socket() as client, suppress(OSError):
        client.connect(('127.0.0.1', 0))

    if hasattr(socket, 'AF_UNIX'):
        with socket.socket(socket.AF_UNIX) as unix_client, suppress(OSError):
            unix_client.connect(str(tmp_path / 'missing.sock'))
