from __future__ import annotations

import logging
import sys
from collections.abc import Hashable, Iterable, Sequence
from typing import TypeVar

T = TypeVar('T', bound=Hashable)


class _OperatorOutputHandler(logging.Handler):
    """Write operator-facing messages to the current stdout stream."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stdout.write(f'{self.format(record)}\n')
        except Exception:
            self.handleError(record)


output_logger = logging.getLogger('theHarvester.output')
_package_logger_level_before_verbose: int | None = None


def configure_logging(*, verbose: bool) -> None:
    """Configure CLI diagnostics without taking ownership from an embedding host."""
    global _package_logger_level_before_verbose

    if not any(isinstance(handler, _OperatorOutputHandler) for handler in output_logger.handlers):
        output_logger.addHandler(_OperatorOutputHandler())
    output_logger.setLevel(logging.INFO)
    output_logger.propagate = False

    root_logger = logging.getLogger()
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(levelname)s %(name)s: %(message)s'))
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.WARNING)

    package_logger = logging.getLogger('theHarvester')
    if verbose and package_logger.level != logging.INFO:
        if _package_logger_level_before_verbose is None:
            _package_logger_level_before_verbose = package_logger.level
        package_logger.setLevel(logging.INFO)
    elif not verbose and _package_logger_level_before_verbose is not None:
        if package_logger.level == logging.INFO:
            package_logger.setLevel(_package_logger_level_before_verbose)
        _package_logger_level_before_verbose = None


def sorted_unique[T: Hashable](items: Iterable[T]) -> list[T]:
    unique_items = list(dict.fromkeys(items))
    unique_items.sort(key=lambda item: str(item))
    return unique_items


def print_section(header: str, items: Iterable[str], separator: str) -> None:
    output_logger.info(header)
    output_logger.info(separator)
    for item in sorted_unique(items):
        output_logger.info(item)


def print_linkedin_sections(
    engines: Sequence[str], people: Sequence[str], links: Sequence[str], separator: str = '---------------------'
) -> None:
    if len(people) == 0 and 'linkedin' in engines:
        output_logger.info('\n[*] No LinkedIn users found.\n\n')
    elif len(people) >= 1:
        output_logger.info(f'\n[*] LinkedIn Users found: {len(people)}')
        output_logger.info(separator)
        for usr in sorted_unique(people):
            output_logger.info(usr)

    if 'linkedin' in engines or 'rocketreach' in engines:
        output_logger.info(f'\n[*] LinkedIn Links found: {len(links)}')
        output_logger.info(separator)
        for link in sorted_unique(links):
            output_logger.info(link)
