"""
Kafka message dispatcher for Triksha.

The in-process Kafka consumer calls dispatch_message() for each message it
reads. This module routes each message by scan_type back into the correct
in-process asyncio queue, where the existing worker tasks pick it up —
the same path used when Kafka is disabled.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

import queue_registry

logger = logging.getLogger("kafka_dispatch")


async def dispatch_message(body: Dict[str, Any]) -> None:
    scan_type = body.get("scan_type")

    if scan_type == "llm":
        q = queue_registry.get_scan_queue()
        if q is None:
            logger.error("scan_queue not registered — cannot dispatch llm scan")
            return
        scan_id = body.get("scan_id")
        scan_config = body.get("scan_config")
        await q.put((scan_id, scan_config))
        logger.info("Dispatched llm scan %s to local scan_queue", scan_id)

    elif scan_type == "mcp":
        q = queue_registry.get_mcp_queue()
        if q is None:
            logger.error("mcp_queue not registered — cannot dispatch mcp scan")
            return
        await q.put((
            body.get("scan_id"),
            body.get("config_content"),
            body.get("file_name"),
            body.get("scan_name"),
            body.get("timeout"),
        ))
        logger.info("Dispatched mcp scan %s to local mcp_queue", body.get("scan_id"))

    elif scan_type == "prd_review":
        q = queue_registry.get_prd_review_queue()
        if q is None:
            logger.error("prd_review_queue not registered — cannot dispatch prd_review")
            return
        review_id = body.get("review_id")
        review_config = body.get("review_config")
        await q.put((review_id, review_config))
        logger.info("Dispatched prd_review %s to local prd_review_queue", review_id)

    elif scan_type == "agent":
        q = queue_registry.get_agent_scan_queue()
        if q is None:
            logger.error("agent_scan_queue not registered — cannot dispatch agent scan")
            return
        scan_id = body.get("scan_id")
        await q.put(scan_id)
        logger.info("Dispatched agent scan %s to local agent_scan_queue", scan_id)

    else:
        logger.warning("Unknown scan_type in Kafka message: %s", scan_type)
