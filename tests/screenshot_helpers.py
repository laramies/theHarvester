"""Screenshot batch behaviour shared by test doubles of ScreenShotter."""

from __future__ import annotations

import asyncio
from pathlib import Path


class FakeScreenshotBatch:
    async def reachable_targets(self, targets: list[str]) -> list[tuple[str, str]]:
        reachable: list[tuple[str, str]] = []
        for subject in targets:
            final_url, status = await self.visit(subject)
            if status:
                reachable.append((subject, final_url))
        return reachable

    async def capture_targets(self, targets, record) -> None:
        async def capture(subject: str, final_url: str) -> tuple[str, str, Path]:
            output_path = self.screenshot_path(subject)
            return subject, await self.take_screenshot(final_url, output_path=output_path), output_path

        tasks = [asyncio.create_task(capture(*target)) for target in targets]
        try:
            for task in asyncio.as_completed(tasks):
                await record(*await task)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, tuple):
                    await record(*outcome)
            raise
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
