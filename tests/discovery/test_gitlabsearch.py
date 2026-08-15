import json
import sys
from pathlib import Path
from typing import Any

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import gitlabsearch
from theHarvester.lib.completed_result import CompletedResult


@pytest.mark.asyncio
async def test_public_discovery_normalizes_evidence_and_uses_bounded_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[dict[str, object]] = []
    projects = [
        {
            'id': 'group/project',
            'default_branch': 'feature/readme',
            'description': 'API.Example.TEST. and false.example.test.evil',
            'name': 'Example project',
            'path_with_namespace': 'group/project',
            'web_url': 'https://gitlab.com/group/project',
        }
    ]
    users = [
        {
            'name': 'Example user',
            'username': 'example',
            'bio': 'Status.Example.TEST.',
            'web_url': 'https://gitlab.com/example',
            'website_url': 'https://Portal.Example.TEST./profile',
            'public_email': 'SECURITY@Example.TEST',
        },
        {
            'name': 'Outsider',
            'username': 'outsider',
            'bio': 'api.notexample.test and example.test.evil',
            'web_url': 'https://gitlab.com/outsider',
            'website_url': 'https://api.notexample.test',
            'public_email': 'outsider@notexample.test',
        },
    ]

    async def fake_fetch_all(
        urls: list[str] | set[str],
        headers: dict[str, str] | None = None,
        proxy: bool = False,
        **_kwargs: Any,
    ) -> list[str]:
        url = next(iter(urls))
        requests.append({'url': url, 'headers': headers, 'proxy': proxy})
        responses = {
            'https://gitlab.com/api/v4/projects?search=example.test&per_page=20': json.dumps(projects),
            'https://gitlab.com/api/v4/projects/group%2Fproject/repository/files/README.md/raw?ref=feature%2Freadme': (
                'Contact Admin@Example.TEST. at docs.example.test; ignore admin@notexample.test'
            ),
            'https://gitlab.com/api/v4/projects?search=*.example.test&per_page=20': '[]',
            'https://gitlab.com/api/v4/users?search=example.test&per_page=10': json.dumps(users),
        }
        if url not in responses:
            raise AssertionError(f'unexpected GitLab request: {url}')
        return [responses[url]]

    monkeypatch.setattr(gitlabsearch.Core, 'get_user_agent', staticmethod(lambda: 'UA'))
    monkeypatch.setattr(gitlabsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = gitlabsearch.SearchGitlab('example.test')

    await search.process(proxy=True)

    assert requests == [
        {'url': url, 'headers': {'User-agent': 'UA'}, 'proxy': True}
        for url in (
            'https://gitlab.com/api/v4/projects?search=example.test&per_page=20',
            'https://gitlab.com/api/v4/projects/group%2Fproject/repository/files/README.md/raw?ref=feature%2Freadme',
            'https://gitlab.com/api/v4/projects?search=*.example.test&per_page=20',
            'https://gitlab.com/api/v4/users?search=example.test&per_page=10',
        )
    ]
    assert await search.get_hostnames() == {
        'api.example.test',
        'docs.example.test',
        'example.test',
        'portal.example.test',
        'status.example.test',
    }
    assert await search.get_emails() == {'admin@example.test', 'security@example.test'}
    assert await search.get_urls() == {
        'https://gitlab.com/example',
        'https://gitlab.com/group/project',
        'https://Portal.Example.TEST./profile',
    }


@pytest.mark.asyncio
async def test_decoded_pages_are_accepted_without_silent_slicing(monkeypatch: pytest.MonkeyPatch) -> None:
    projects = [
        {
            'id': index,
            'default_branch': None,
            'description': f'project-{index}.example.test',
        }
        for index in range(1, 22)
    ]
    users = [{'public_email': f'user-{index}@example.test'} for index in range(1, 12)]

    async def fake_fetch_all(urls: list[str] | set[str], **_kwargs: Any) -> list[object]:
        url = next(iter(urls))
        if 'projects?search=example.test&' in url:
            return [projects]
        if 'projects?search=*.example.test&' in url:
            return [[]]
        if '/users?' in url:
            return [users]
        raise AssertionError(f'unexpected GitLab request: {url}')

    monkeypatch.setattr(gitlabsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = gitlabsearch.SearchGitlab('example.test')

    await search.process()

    hostnames = await search.get_hostnames()
    emails = await search.get_emails()
    assert len(hostnames) == 21
    assert 'project-21.example.test' in hostnames
    assert len(emails) == 11
    assert 'user-11@example.test' in emails


@pytest.mark.asyncio
async def test_gitlab_urls_reach_completed_jsonl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed_results: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args: object) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed_results.append(result)

    class FakeGitlab:
        def __init__(self, domain: str) -> None:
            assert domain == 'example.test'

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_emails(self) -> set[str]:
            return set()

        async def get_urls(self) -> set[str]:
            return {'https://gitlab.com/group/project'}

    report = tmp_path / 'gitlab-report'
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(gitlabsearch, 'SearchGitlab', FakeGitlab)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.test', '-b', 'gitlab', '-f', str(report)])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert completed_results[0].results == (('url', 'https://gitlab.com/group/project'),)
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert {'type': 'url', 'value': 'https://gitlab.com/group/project', 'sources': ['gitlab']} in records
