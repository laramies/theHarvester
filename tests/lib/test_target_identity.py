from __future__ import annotations

import pytest

from theHarvester.lib.target_identity import normalize_enumeration_target, normalize_saved_target


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        (' EXAMPLE.TEST. ', 'example.test'),
        ('AS064496', 'AS64496'),
        ('BÜCHER.EXAMPLE', 'xn--bcher-kva.example'),
        ('2001:0db8::1', '2001:db8::1'),
    ],
)
def test_normalize_enumeration_target_preserves_execution_admission(value: str, expected: str) -> None:
    assert normalize_enumeration_target(value) == expected


@pytest.mark.parametrize(
    ('value', 'message'),
    [
        ('Example Company', 'Target must be a valid hostname'),
        ('192.0.2.0/24', 'Target must be a hostname or IP address'),
    ],
)
def test_normalize_enumeration_target_preserves_current_run_rejections(value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_enumeration_target(value)


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        (' EXAMPLE.TEST. ', 'example.test'),
        ('www.example.test', 'www.example.test'),
        ('AS064496', 'AS64496'),
        ('192.0.2.1/24', '192.0.2.0/24'),
        (' Example Company ', 'Example Company'),
    ],
)
def test_normalize_saved_target_preserves_persisted_identity(value: object, expected: str) -> None:
    assert normalize_saved_target(value) == expected
