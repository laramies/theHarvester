import re
from pathlib import Path


def test_agent_guidance_relative_links_resolve() -> None:
    guide = Path('AGENTS.md')
    targets = [
        link.split('#', 1)[0]
        for link in re.findall(r'\]\(([^)]+)\)', guide.read_text())
        if '://' not in link and not link.startswith('#')
    ]

    assert targets
    assert all((guide.parent / target).is_file() for target in targets)
