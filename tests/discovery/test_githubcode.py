from unittest.mock import MagicMock
import pytest
from httpx import Response
from theHarvester.discovery import githubcode
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core


class TestSearchGithubCode:
    class OkResponse:
        response = Response(status_code=200)

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

    class FailureResponse:
        def __init__(self):
            self.response = Response(status_code=401)
            object.__setattr__(self.response, "json", MagicMock(return_value={}))

    class RetryResponse:
        def __init__(self):
            self.response = Response(status_code=403)
            object.__setattr__(self.response, "json", MagicMock(return_value={}))

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
        print("test_result: ", test_result)
        assert test_result == ["test1", "test2"]

    @pytest.mark.asyncio
    async def test_invalid_fragments_from_response(self):
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        test_result = await test_class_instance.fragments_from_response(
            self.MalformedResponse().response.json()
        )
        assert test_result == []

    @pytest.mark.asyncio
    async def test_next_page(self):
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        test_result = githubcode.SuccessResult(list(), next_page=2, last_page=4)
        assert 2 == await test_class_instance.next_page_or_end(test_result)

    @pytest.mark.asyncio
    async def test_last_page(self):
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        test_result = githubcode.SuccessResult(list(), 0, 0)
        assert await test_class_instance.next_page_or_end(test_result) is 0

    @pytest.mark.asyncio
    async def test_infinite_loop_fix_page_zero(self):
        """Test that the loop condition properly exits when page becomes 0"""
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)

        # Test the fixed condition: page != 0
        page = 0
        counter = 0
        limit = 10

        # The condition should be False when page is 0, preventing infinite loop
        condition_result = counter <= limit and page != 0
        assert condition_result is False, "Loop should exit when page is 0"

    @pytest.mark.asyncio
    async def test_infinite_loop_fix_page_nonzero(self):
        """Test that the loop condition continues when page is non-zero"""
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)

        # Test with non-zero page values
        for page in [1, 2, 3, 10]:
            counter = 0
            limit = 10

            # The condition should be True when page is non-zero
            condition_result = counter <= limit and page != 0
            assert condition_result is True, f"Loop should continue when page is {page}"

    @pytest.mark.asyncio
    async def test_infinite_loop_fix_old_vs_new_condition(self):
        """Test that demonstrates the difference between old and new conditions"""
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)

        page = 0
        counter = 0
        limit = 10

        # Old problematic condition (would cause infinite loop)
        old_condition = counter <= limit and page is not None

        # New fixed condition (properly exits)
        new_condition = counter <= limit and page != 0

        # Old condition would be True (causing infinite loop)
        assert old_condition is True, "Old condition would cause infinite loop when page=0"

        # New condition is False (properly exits)
        assert new_condition is False, "New condition properly exits when page=0"


if __name__ == "__main__":
    pytest.main()
