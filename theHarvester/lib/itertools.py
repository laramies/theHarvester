# -*- coding: utf-8 -*-

"""
=========
Itertools
=========

Async iterator / generator tools.
"""

from __future__ import absolute_import, division, print_function

import asyncio

from typing import Any, AsyncIterable

# TODO: need big focus on performance and results parsing, now does the basic.

#####################################################################
# DNS FORCE
#####################################################################

def merge_async_generators(
        *aiters: AsyncIterable[Any]) -> AsyncIterable[Any]:
    """
    Merge several async generators into a single one.
    The merged generator provides items in the order of availability.

    Parameters
    ----------
    aiters: AsyncIterable.
        A list of iterators / generators.

    Returns
    -------
    out: AsyncIterable.
        The merged iterator / generator.
    """
    # merge async iterators, proof of concept
    queue = asyncio.Queue(1)
    async def drain(aiter):
        async for item in aiter:
            await queue.put(item)
    async def merged():
        while not all(task.done() for task in tasks) or not queue.empty():
            yield await queue.get()
    tasks = [asyncio.create_task(drain(aiter)) for aiter in aiters]
    return merged()
