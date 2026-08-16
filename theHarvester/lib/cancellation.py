from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable


async def drain_tasks_after_cancellation(
    tasks: Iterable[asyncio.Task[Any]],
    *,
    cancel: bool,
) -> tuple[asyncio.CancelledError, ...]:
    """Finish owned tasks while deferring repeated caller cancellation."""
    owned_tasks = tuple(tasks)
    if cancel:
        for task in owned_tasks:
            if not task.done():
                task.cancel()
    pending = {task for task in owned_tasks if not task.done()}
    interruptions: list[asyncio.CancelledError] = []
    while pending:
        try:
            _done, pending = await asyncio.wait(pending)
        except asyncio.CancelledError as error:
            interruptions.append(error)
    for task in owned_tasks:
        if not task.cancelled():
            task.exception()
    return tuple(interruptions)
