"""Credential boundaries that keep provider code independent of configuration files.

Production access retains Core's existing file precedence. In-memory access lets
tests and embedded callers provide credentials without filesystem or global state.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from theHarvester.lib.core import Core

if TYPE_CHECKING:
    from collections.abc import Mapping


class FileSystemCredentialAdapter:
    """Read production credentials through Core's existing file precedence."""

    @staticmethod
    def get(provider: str, field: str = 'key') -> str:
        return Core.api_keys()[provider][field]


@dataclass(frozen=True)
class InMemoryCredentialAdapter:
    """Provide credentials directly for isolated tests and programmatic callers."""

    credentials: Mapping[str, Mapping[str, str]]

    def get(self, provider: str, field: str = 'key') -> str:
        return self.credentials[provider][field]


type CredentialAdapter = FileSystemCredentialAdapter | InMemoryCredentialAdapter
