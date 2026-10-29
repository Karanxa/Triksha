"""
ProxyLlm — Custom ADK BaseLlm that calls Gemini through an optional LLM proxy.

The standard google-genai SDK hardcodes its URL as
    https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
but the proxy exposes:
    {LLM_PROXY_BASE_URL}/{model}/:generateContent

This module provides a drop-in BaseLlm subclass so the ADK Agent,
InMemoryRunner and the full tool-calling loop work transparently
while all LLM traffic goes through the proxy.
"""

import os
import re
import json
import asyncio
import logging
from typing import AsyncGenerator, Optional

import httpx
from pydantic import ConfigDict

from google.adk.models.base_llm import BaseLlm
from proxy_auth import get_bearer_token
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

logger = logging.getLogger(__name__)

_PROXY_BASE = os.getenv("LLM_PROXY_BASE_URL", "")
_DEFAULT_MODEL = "gemini-2.5-flash"
_REQUEST_TIMEOUT = 120  # seconds — tool-calling turns can be slow
_MAX_RETRIES = 4         # retry up to 4 times on 429 / 503 / 5xx
_RETRY_BASE_DELAY = 5    # first retry after ~5s, then 10s, 20s, 40s


class ProxyLlm(BaseLlm):
    """ADK-compatible LLM that routes every request through the configured LLM proxy."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # -- configurable fields --------------------------------------------------
    model: str = _DEFAULT_MODEL
    api_key: Optional[str] = None
    proxy_base_url: str = _PROXY_BASE
    request_timeout: int = _REQUEST_TIMEOUT

    # -------------------------------------------------------------------------
    # BaseLlm interface
    # -------------------------------------------------------------------------
    @classmethod
    def supported_models(cls) -> list[str]:
        # Let LlmRegistry know we handle anything starting with "proxy/"
        return [r"proxy/.*"]

    async def generate_content_async(
        self,
        llm_request: LlmRequest,
        stream: bool = False,
    ) -> AsyncGenerator[LlmResponse, None]:
        """Call the proxy and yield a single, complete LlmResponse."""

        key = self._resolve_api_key()
        if not key:
            yield LlmResponse(
                error_code="401",
                error_message=(
                    "GEMINI_API_KEY not set — cannot call proxy. "
                    "Export the key or pass api_key= to ProxyLlm."
                ),
            )
            return

        # --- Build the proxy payload ----------------------------------------
        payload = self._build_payload(llm_request)
        url = f"{self.proxy_base_url}/{self.model}/:generateContent"
        headers = {
            "Ocp-Apim-Subscription-Key": key,
            "Content-Type": "application/json",
        }
        # Add OAuth Bearer token (proxy auth requirement)
        bearer = get_bearer_token()
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"

        logger.debug("ProxyLlm → POST %s  (contents=%d)", url, len(payload.get("contents", [])))

        # --- Call proxy with retry on rate-limit / transient errors ----------
        resp = None
        last_error_msg = ""

        for attempt in range(_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=self.request_timeout) as client:
                    resp = await client.post(url, json=payload, headers=headers)
            except httpx.TimeoutException:
                last_error_msg = f"proxy request timed out after {self.request_timeout}s"
                if attempt < _MAX_RETRIES:
                    delay = _RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "proxy timeout (attempt %d/%d), retrying in %ds…",
                        attempt + 1, _MAX_RETRIES + 1, delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                yield LlmResponse(error_code="504", error_message=last_error_msg)
                return
            except Exception as exc:
                last_error_msg = f"proxy request failed: {exc}"
                if attempt < _MAX_RETRIES:
                    delay = _RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "proxy error (attempt %d/%d): %s — retrying in %ds…",
                        attempt + 1, _MAX_RETRIES + 1, exc, delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                yield LlmResponse(error_code="502", error_message=last_error_msg)
                return

            # Retry on 429 (rate limit) and 5xx (server errors)
            if resp.status_code == 429 or resp.status_code >= 500:
                error_text = resp.text[:300]
                # Try to parse retry-after hint from the response
                retry_after = None
                try:
                    body = resp.json()
                    msg = body.get("message", "")
                    # Parse "Try again in 20 seconds" style messages
                    match = re.search(r"(\d+)\s*seconds?", msg)
                    if match:
                        retry_after = int(match.group(1))
                except Exception:
                    pass

                if attempt < _MAX_RETRIES:
                    delay = retry_after if retry_after else _RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "proxy %d (attempt %d/%d): %s — retrying in %ds…",
                        resp.status_code, attempt + 1, _MAX_RETRIES + 1,
                        error_text[:200], delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                else:
                    logger.error(
                        "proxy %d after %d attempts: %s",
                        resp.status_code, _MAX_RETRIES + 1, error_text,
                    )
                    yield LlmResponse(
                        error_code=str(resp.status_code),
                        error_message=f"proxy HTTP {resp.status_code} after {_MAX_RETRIES + 1} attempts: {error_text}",
                    )
                    return

            # Non-retryable error
            if resp.status_code != 200:
                error_text = resp.text[:500]
                logger.error("proxy returned %d: %s", resp.status_code, error_text)
                yield LlmResponse(
                    error_code=str(resp.status_code),
                    error_message=f"proxy HTTP {resp.status_code}: {error_text}",
                )
                return

            # Success — break out of retry loop
            break

        if resp is None:
            yield LlmResponse(
                error_code="502",
                error_message=last_error_msg or "proxy request failed after all retries",
            )
            return

        # --- Parse the response -----------------------------------------------
        data = resp.json()
        content = self._parse_response(data)

        if content is None:
            yield LlmResponse(
                error_code="500",
                error_message=f"Could not parse proxy response: {json.dumps(data)[:500]}",
            )
            return

        yield LlmResponse(content=content)

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------
    def _resolve_api_key(self) -> Optional[str]:
        return self.api_key or os.environ.get("GEMINI_API_KEY")

    def _build_payload(self, llm_request: LlmRequest) -> dict:
        """Convert LlmRequest → proxy-compatible JSON dict."""

        # Contents
        contents = []
        for c in llm_request.contents:
            contents.append(c.model_dump(exclude_none=True, by_alias=True))

        payload: dict = {"contents": contents}

        # System instruction
        cfg = llm_request.config
        if cfg and cfg.system_instruction:
            si = cfg.system_instruction
            if isinstance(si, str):
                payload["systemInstruction"] = {
                    "parts": [{"text": si}]
                }
            elif isinstance(si, types.Content):
                payload["systemInstruction"] = si.model_dump(
                    exclude_none=True, by_alias=True
                )

        # Tools
        if cfg and cfg.tools:
            tools_list = []
            for tool in cfg.tools:
                if isinstance(tool, types.Tool):
                    tools_list.append(
                        tool.model_dump(exclude_none=True, by_alias=True)
                    )
                elif isinstance(tool, dict):
                    tools_list.append(tool)
            if tools_list:
                payload["tools"] = tools_list

        # Tool config (e.g. function_calling_config)
        if cfg and cfg.tool_config:
            tc = cfg.tool_config
            if isinstance(tc, types.ToolConfig):
                payload["toolConfig"] = tc.model_dump(
                    exclude_none=True, by_alias=True
                )
            elif isinstance(tc, dict):
                payload["toolConfig"] = tc

        # Generation config — proxy enforces a hard 1000-token output cap
        _MAX_TOKENS_CAP = 1000
        gen_config: dict = {}
        if cfg:
            if cfg.temperature is not None:
                gen_config["temperature"] = cfg.temperature
            if cfg.max_output_tokens is not None:
                gen_config["maxOutputTokens"] = min(
                    cfg.max_output_tokens, _MAX_TOKENS_CAP
                )
            if cfg.top_p is not None:
                gen_config["topP"] = cfg.top_p
            if cfg.top_k is not None:
                gen_config["topK"] = cfg.top_k
            if cfg.stop_sequences:
                gen_config["stopSequences"] = cfg.stop_sequences
        if "maxOutputTokens" not in gen_config:
            gen_config["maxOutputTokens"] = _MAX_TOKENS_CAP
        if "temperature" not in gen_config:
            gen_config["temperature"] = 0.5
        payload["generationConfig"] = gen_config

        # NOTE: proxy does not support thinkingConfig — do not add it.
        # Gemini 2.5 Flash thinking tokens are handled internally by proxy.

        return payload

    @staticmethod
    def _parse_response(data: dict) -> Optional[types.Content]:
        """Parse proxy JSON response → types.Content."""

        candidates = data.get("candidates")
        if not candidates:
            return None

        candidate = candidates[0]
        raw_content = candidate.get("content")
        if not raw_content:
            return None

        # Build parts
        parts: list[types.Part] = []
        for raw_part in raw_content.get("parts", []):
            if "text" in raw_part:
                parts.append(types.Part.from_text(text=raw_part["text"]))
            elif "functionCall" in raw_part:
                fc = raw_part["functionCall"]
                parts.append(
                    types.Part(
                        function_call=types.FunctionCall(
                            name=fc.get("name", ""),
                            args=fc.get("args", {}),
                        )
                    )
                )
            # thoughtSignature and other metadata are ignored

        if not parts:
            return None

        role = raw_content.get("role", "model")
        return types.Content(role=role, parts=parts)
