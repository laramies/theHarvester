from collections.abc import Mapping
from dataclasses import dataclass

from theHarvester.lib.core import Core


class FileSystemCredentialAdapter:
    @staticmethod
    def get(provider: str, field: str = 'key') -> str:
        return Core.api_keys()[provider][field]


@dataclass(frozen=True)
class InMemoryCredentialAdapter:
    credentials: Mapping[str, Mapping[str, str]]

    def get(self, provider: str, field: str = 'key') -> str:
        return self.credentials[provider][field]


type CredentialAdapter = FileSystemCredentialAdapter | InMemoryCredentialAdapter
