"""Optional Kafka scan queue client."""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger("kafka_client")

# ---------------------------------------------------------------------------
# Configuration (all from env, with safe defaults for local dev)
# ---------------------------------------------------------------------------
USE_KAFKA: bool = os.getenv("TRIKSHA_USE_KAFKA", "false").lower() == "true"

BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

# All scan types share one topic, differentiated by the "scan_type" field.
TOPIC_SCANS: str = os.getenv("KAFKA_TOPIC_SCANS", "triksha-scans")

CONSUMER_GROUP: str = os.getenv("KAFKA_CONSUMER_GROUP", "triksha-scan-workers")

PRODUCE_TIMEOUT_SECONDS: int = int(os.getenv("KAFKA_PRODUCE_TIMEOUT", "10"))

SECURITY_PROTOCOL: str = os.getenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
SASL_MECHANISM: Optional[str] = os.getenv("KAFKA_SASL_MECHANISM") or None
SASL_USERNAME: Optional[str] = os.getenv("KAFKA_SASL_USERNAME") or None
SASL_PASSWORD: Optional[str] = os.getenv("KAFKA_SASL_PASSWORD") or None


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class KafkaProduceError(Exception):
    """Raised when producing a message to Kafka fails."""


# ---------------------------------------------------------------------------
# Shared producer lifecycle
# ---------------------------------------------------------------------------
_producer = None  # type: ignore  # aiokafka.AIOKafkaProducer when started


def _common_client_kwargs() -> Dict[str, Any]:
    """Build connection kwargs shared by the producer and consumer."""
    kwargs: Dict[str, Any] = {
        "bootstrap_servers": BOOTSTRAP_SERVERS,
        "security_protocol": SECURITY_PROTOCOL,
    }
    if SASL_MECHANISM:
        kwargs["sasl_mechanism"] = SASL_MECHANISM
        if SASL_USERNAME is not None:
            kwargs["sasl_plain_username"] = SASL_USERNAME
        if SASL_PASSWORD is not None:
            kwargs["sasl_plain_password"] = SASL_PASSWORD
    return kwargs


async def start_producer() -> None:
    """
    Start the shared Kafka producer. Idempotent — safe to call on every app
    startup. Does nothing when Kafka is disabled.
    """
    global _producer
    if not USE_KAFKA:
        return
    if _producer is not None:
        return

    try:
        from aiokafka import AIOKafkaProducer
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise KafkaProduceError(
            "aiokafka is not installed but TRIKSHA_USE_KAFKA=true. "
            "Add 'aiokafka' to requirements.txt."
        ) from exc

    producer = AIOKafkaProducer(
        acks="all",
        # enable_idempotence guarantees no duplicate produces on retries.
        enable_idempotence=True,
        request_timeout_ms=PRODUCE_TIMEOUT_SECONDS * 1000,
        **_common_client_kwargs(),
    )
    await producer.start()
    _producer = producer
    logger.info("Kafka producer started (bootstrap=%s)", BOOTSTRAP_SERVERS)


async def stop_producer() -> None:
    """Flush and stop the shared Kafka producer. Idempotent."""
    global _producer
    if _producer is not None:
        try:
            await _producer.stop()
            logger.info("Kafka producer stopped")
        finally:
            _producer = None


def is_kafka_enabled() -> bool:
    """Check whether the Kafka feature flag is active."""
    return USE_KAFKA


# ---------------------------------------------------------------------------
# Produce
# ---------------------------------------------------------------------------
async def produce_message(
    message_body: Dict[str, Any],
    key: Optional[str] = None,
    topic: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Produce a single message to the Kafka scans topic.

    Parameters
    ----------
    message_body : dict
        JSON-serialisable payload. Always includes a ``scan_type`` field used
        by the consumer to route the message.
    key : str, optional
        Partition key. We use ``scan_id`` / ``review_id`` so all messages for a
        given scan land on the same partition and are processed in order.
    topic : str, optional
        Override the destination topic. Defaults to ``KAFKA_TOPIC_SCANS``.

    Returns
    -------
    dict
        ``{"topic", "partition", "offset", "message_id"}`` for the produced record.

    Raises
    ------
    KafkaProduceError
        If the produce call fails.
    """
    if _producer is None:
        # Lazy-start so producing works even if startup hook was skipped.
        try:
            await start_producer()
        except Exception as _start_exc:
            raise KafkaProduceError(f"Kafka producer failed to start: {_start_exc}") from _start_exc
    if _producer is None:
        raise KafkaProduceError("Kafka producer is not available (is Kafka enabled?)")

    dest_topic = topic or TOPIC_SCANS
    message_id = message_body.get("message_id") or uuid.uuid4().hex

    payload = json.dumps(message_body, default=str).encode("utf-8")
    key_bytes = key.encode("utf-8") if key else None

    try:
        record = await _producer.send_and_wait(
            dest_topic, value=payload, key=key_bytes
        )
        logger.info(
            "Kafka message produced: topic=%s partition=%s offset=%s key=%s",
            record.topic,
            record.partition,
            record.offset,
            key,
        )
        return {
            "topic": record.topic,
            "partition": record.partition,
            "offset": record.offset,
            "message_id": message_id,
        }
    except Exception as exc:  # aiokafka raises various KafkaError subclasses
        logger.error("Kafka produce failed: %s", exc)
        raise KafkaProduceError(f"Kafka produce failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Convenience wrappers per scan type
# ---------------------------------------------------------------------------
async def enqueue_llm_scan(
    scan_id: str,
    scan_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Enqueue an LLM scan via Kafka."""
    message_body = {
        "scan_type": "llm",
        "scan_id": scan_id,
        "scan_config": scan_config,
        "message_id": scan_id,
    }
    return await produce_message(message_body, key=scan_id)


async def enqueue_mcp_scan(
    scan_id: str,
    config_content: str,
    file_name: str,
    scan_name: str,
    timeout: int,
) -> Dict[str, Any]:
    """Enqueue an MCP scan via Kafka."""
    message_body = {
        "scan_type": "mcp",
        "scan_id": scan_id,
        "config_content": config_content,
        "file_name": file_name,
        "scan_name": scan_name,
        "timeout": timeout,
        "message_id": scan_id,
    }
    return await produce_message(message_body, key=scan_id)


async def enqueue_agent_scan(
    scan_id: str,
    scan_record: Dict[str, Any],
) -> Dict[str, Any]:
    """Enqueue an Agent scan via Kafka."""
    message_body = {
        "scan_type": "agent",
        "scan_id": scan_id,
        "scan_record": scan_record,
        "message_id": scan_id,
    }
    return await produce_message(message_body, key=scan_id)


async def enqueue_prd_review(
    review_id: str,
    review_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Enqueue a PRD security review via Kafka."""
    message_body = {
        "scan_type": "prd_review",
        "review_id": review_id,
        "review_config": review_config,
        "message_id": review_id,
    }
    return await produce_message(message_body, key=review_id)


async def enqueue_fdp_event(
    event_id: str,
    event_payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Enqueue an FDP ingestion event via Kafka."""
    message_body = {
        "scan_type": "fdp_ingest",
        "event_id": event_id,
        "payload": event_payload,
        "message_id": event_id,
    }
    return await produce_message(message_body, key=event_id)
