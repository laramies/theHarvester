from __future__ import annotations

import ast
import re
from pathlib import Path


def _executable_source_names() -> list[str]:
    tree = ast.parse(Path('theHarvester/__main__.py').read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name)
            and node.left.id == 'engineitem'
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and isinstance(node.comparators[0].value, str)
        ):
            names.append(node.comparators[0].value)
    return names


def test_readme_lists_each_executable_source_once() -> None:
    readme = Path('README.md').read_text()
    matrix = readme.split('<summary><strong>View the source and result matrix</strong></summary>', 1)[1].split('</details>', 1)[0]
    documented = re.findall(r'^\| `([^`]+)` \|', matrix, flags=re.MULTILINE)
    executable = _executable_source_names()

    assert len(executable) == len(set(executable)) == 55
    assert len(documented) == len(set(documented)) == 55
    assert set(documented) == set(executable)
    assert {'securitytrails', 'shodaninternetdb'}.isdisjoint(documented)
