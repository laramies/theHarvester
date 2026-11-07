from unittest.mock import MagicMock
import pytest
from httpx import Response
from theHarvester.discovery import githubcode
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import CONFIG_DIRS, Core

# Captured at collection time: other tests in this package replace Core.github_key without restoring it.
_GITHUB_KEY_ACCESSOR = Core.__dict__['github_key']


@pytest.mark.parametrize('configured_provider', ['GitHub', 'Github'])
def test_github_code_reads_a_key_configured_under_a_case_variant_provider_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path, configured_provider: str
) -> None:
    monkeypatch.setattr(Core, 'github_key', _GITHUB_KEY_ACCESSOR)
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setattr(Core, 'quiet', True)
    config_dir = CONFIG_DIRS[0].expanduser()
    config_dir.mkdir(mode=0o700)
    (config_dir / 'api-keys.yaml').write_text(
        f'apikeys:\n  {configured_provider}:\n    key: github-token\n', encoding='utf-8'
    )

    search = githubcode.SearchGithubCode(word='example.com', limit=10)

    assert search.key == 'github-token'
    assert search.headers['Authorization'] == 'token github-token'


class TestSearchGithubCode:
    class OkResponse:
        # Mocking the json method properly
        def __init__(self):
            self.response = Response(status_code=200)
            object.__setattr__(
                self.response,
                "json",
                MagicMock(
                    return_value={
                        "items": [
                            {"text_matches": [{"fragment": "test1"}]},
                            {"text_matches": [{"fragment": "test2"}]},
                        ]
                    }
                ),
            )

    class MalformedResponse:
        def __init__(self):
            self.response = Response(status_code=200)
            object.__setattr__(
                self.response,
                "json",
                MagicMock(
                    return_value={
                        "items": [
                            {"fail": True},
                            {"text_matches": []},
                            {"text_matches": [{"weird": "result"}]},
                        ]
                    }
                ),
            )

    @pytest.mark.asyncio
    async def test_missing_key(self):
        with pytest.raises(MissingKey):
            Core.github_key = MagicMock(return_value=None)  # type: ignore[method-assign]
            githubcode.SearchGithubCode(word="test", limit=500)

    @pytest.mark.asyncio
    async def test_fragments_from_response(self):
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        test_result = await test_class_instance.fragments_from_response(
            self.OkResponse().response.json()
        )
        assert test_result == ["test1", "test2"]

    @pytest.mark.asyncio
    async def test_invalid_fragments_from_response(self):
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        test_result = await test_class_instance.fragments_from_response(
            self.MalformedResponse().response.json()
        )
        assert test_result == []


if __name__ == "__main__":
    pytest.main()
