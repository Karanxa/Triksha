"""
Shared queue registry for Kafka dispatch.

main.py registers its asyncio queues here at startup so that kafka_dispatch
can put messages back into the in-process workers without a circular import.
"""

from __future__ import annotations

import asyncio
from typing import Optional

_scan_queue: Optional[asyncio.Queue] = None
_mcp_queue: Optional[asyncio.Queue] = None
_prd_review_queue: Optional[asyncio.Queue] = None
_agent_scan_queue: Optional[asyncio.Queue] = None


def register_scan_queue(q: asyncio.Queue) -> None:
    global _scan_queue
    _scan_queue = q


def register_mcp_queue(q: asyncio.Queue) -> None:
    global _mcp_queue
    _mcp_queue = q


def register_prd_review_queue(q: asyncio.Queue) -> None:
    global _prd_review_queue
    _prd_review_queue = q


def register_agent_scan_queue(q: asyncio.Queue) -> None:
    global _agent_scan_queue
    _agent_scan_queue = q


def get_scan_queue() -> Optional[asyncio.Queue]:
    return _scan_queue


def get_mcp_queue() -> Optional[asyncio.Queue]:
    return _mcp_queue


def get_prd_review_queue() -> Optional[asyncio.Queue]:
    return _prd_review_queue


def get_agent_scan_queue() -> Optional[asyncio.Queue]:
    return _agent_scan_queue
