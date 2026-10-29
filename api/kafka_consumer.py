"""In-process Kafka consumer for scan dispatch."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import kafka_client

logger = logging.getLogger("kafka_consumer")

_consumer = None  # type: ignore  # aiokafka.AIOKafkaConsumer when running
_consumer_task: Optional[asyncio.Task] = None
_stop_requested = False


async def _consume_loop() -> None:
    """Main consume loop. Reads messages and dispatches them by scan_type."""
    from aiokafka import AIOKafkaConsumer
    from kafka_dispatch import dispatch_message

    global _consumer

    consumer = AIOKafkaConsumer(
        kafka_client.TOPIC_SCANS,
        group_id=kafka_client.CONSUMER_GROUP,
        # Manual commit so we only advance after a message is accepted.
        enable_auto_commit=False,
        auto_offset_reset="earliest",
        **kafka_client._common_client_kwargs(),
    )
    await consumer.start()
    _consumer = consumer
    logger.info(
        "Kafka consumer started: topic=%s group=%s bootstrap=%s",
        kafka_client.TOPIC_SCANS,
        kafka_client.CONSUMER_GROUP,
        kafka_client.BOOTSTRAP_SERVERS,
    )

    try:
        async for msg in consumer:
            if _stop_requested:
                break
            try:
                body = json.loads(msg.value.decode("utf-8"))
            except (ValueError, AttributeError) as exc:
                logger.error(
                    "Skipping malformed Kafka message at offset %s: %s",
                    msg.offset,
                    exc,
                )
                await consumer.commit()
                continue

            try:
                # Handlers are non-blocking: they spawn a background task and
                # return quickly. So awaiting dispatch_message does not stall
                # the consumer for the duration of a scan.
                await dispatch_message(body)
            except Exception as exc:
                # A dispatch failure should not crash the consumer. The message
                # is committed regardless to avoid a poison-pill hot loop;
                # failures are logged for investigation.
                logger.error(
                    "Error dispatching Kafka message (scan_type=%s, offset=%s): %s",
                    body.get("scan_type"),
                    msg.offset,
                    exc,
                )

            await consumer.commit()
    except asyncio.CancelledError:
        logger.info("Kafka consumer loop cancelled")
        raise
    finally:
        try:
            await consumer.stop()
        except Exception:
            pass
        _consumer = None
        logger.info("Kafka consumer stopped")


async def start_consumer() -> None:
    """
    Start the background consumer task. Idempotent and a no-op when Kafka is
    disabled. Call from the FastAPI startup hook.
    """
    global _consumer_task, _stop_requested
    if not kafka_client.is_kafka_enabled():
        return
    if _consumer_task is not None and not _consumer_task.done():
        return

    try:
        import aiokafka  # noqa: F401
    except ImportError:
        logger.error(
            "aiokafka is not installed but TRIKSHA_USE_KAFKA=true — "
            "Kafka consumer will not start. Add 'aiokafka' to requirements.txt."
        )
        return

    _stop_requested = False
    _consumer_task = asyncio.create_task(_consume_loop(), name="kafka-consumer")
    logger.info("Kafka consumer task created")


async def stop_consumer() -> None:
    """Stop the background consumer task. Idempotent. Call from shutdown hook."""
    global _consumer_task, _stop_requested
    _stop_requested = True

    if _consumer is not None:
        # Nudge the loop to wake up from `async for` if it is blocked on poll.
        try:
            await _consumer.stop()
        except Exception:
            pass

    if _consumer_task is not None:
        _consumer_task.cancel()
        try:
            await _consumer_task
        except (asyncio.CancelledError, Exception):
            pass
        _consumer_task = None
