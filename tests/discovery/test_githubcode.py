from theHarvester.discovery import githubcode
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core
from unittest.mock import MagicMock
from requests import Response
import pytest


class TestSearchGithubCode:

    def test_missing_key(self):
        with pytest.raises(MissingKey):
            githubcode.SearchGithubCode(word="test", limit=500)


    def test_fragments_from_response(self):
        Core.github_key = MagicMock(return_value="lol")
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        response = Response()
        json = {
            "items": [
                {
                    "text_matches": [
                        {
                            "fragment": "test1"
                        }
                    ]
                },
                {
                    "text_matches": [
                        {
                            "fragment": "test2"
                        }
                    ]
                }
            ]
        }
        response.json = MagicMock(return_value=json)
        test_result = test_class_instance.fragments_from_response(response)
        assert test_result == ["test1", "test2"]

    def test_fail_fragments_from_response(self):
        Core.github_key = MagicMock(return_value="lol")
        test_class_instance = githubcode.SearchGithubCode(word="test", limit=500)
        response = Response()
        json = {
            "items": [
                {
                    "fail": True
                },
                {
                    "text_matches": []
                },
                {
                    "text_matches": [
                        {
                            "weird": "result"
                        }
                    ]
                }
            ]
        }
        response.json = MagicMock(return_value=json)
        test_result = test_class_instance.fragments_from_response(response)
        assert test_result == []

    if __name__ == '__main__':
        pytest.main()

