from unittest.mock import MagicMock
import pytest
from _pytest.mark.structures import MarkDecorator
from requests import Response
from theHarvester.discovery import githubcode
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core

pytestmark: MarkDecorator = pytest.mark.asyncio


class TestSearchGithubCode:
    class OkResponse:
        response = Response()

        # Mocking the json method properly
        def __init__(self):
            self.response = Response()
            self.response.status_code = 200
            self.response.json = MagicMock(
                return_value={
                    "items": [
                        {"text_matches": [{"fragment": "test1"}]},
                        {"text_matches": [{"fragment": "test2"}]},
                    ]
                }
            )

    class FailureResponse:
        response = Response()

        def __init__(self):
            self.response = Response()
            self.response.status_code = 401
            self.response.json = MagicMock(return_value={})

    class RetryResponse:
        def __init__(self):
            self.response = Response()
            self.response.status_code = 403
            self.response.json = MagicMock(return_value={})

    class MalformedResponse:
        response = Response()

        def __init__(self):
            self.response = Response()
            self.response.status_code = 200
            self.response.json = MagicMock(
                return_value={
                    "items": [
                        {"fail": True},
                        {"text_matches": []},
                        {"text_matches": [{"weird": "result"}]},
                    ]
                }
            )

    async def test_missing_key(self):
        with pytest.raises(MissingKey):
            Core.github_key = MagicMock(return_value=None)
            githubcode.SearchGithubCode(word="test", limit=500)

    async def test_fragments_from_response(self):
        Core.github_key = MagicMock(return_value="test_key")
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        test_result = await test_class_instance.fragments_from_response(
            self.OkResponse().response.json()
        )
        print("test_result: ", test_result)
        assert test_result == ["test1", "test2"]

    async def test_invalid_fragments_from_response(self):
        Core.github_key = MagicMock(return_value="test_key")
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        test_result = await test_class_instance.fragments_from_response(
            self.MalformedResponse().response.json()
        )
        assert test_result == []

    async def test_next_page(self):
        Core.github_key = MagicMock(return_value="test_key")
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        test_result = githubcode.SuccessResult(list(), next_page=2, last_page=4)
        assert 2 == await test_class_instance.next_page_or_end(test_result)

    async def test_last_page(self):
        Core.github_key = MagicMock(return_value="test_key")
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        test_result = githubcode.SuccessResult(list(), 0, 0)
        assert await test_class_instance.next_page_or_end(test_result) is 0


if __name__ == "__main__":
    pytest.main()
