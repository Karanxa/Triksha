"""
PluggableLlm — a custom ADK BaseLlm for Triksha.

A first-party, multi-provider model
for the autonomous agent scanner. No LiteLLM — each provider is driven through
its OFFICIAL SDK / API, which is more robust and predictable than a generic
wrapper:

    - gemini    → Google GenAI public API (reuses the proven Gemini tool-calling
                  translation; identical request/response shape to the old adapter)
    - openai    → openai SDK   (chat.completions with tools)
    - anthropic → anthropic SDK (messages with tools)

Provider + model come from llm_providers (LLM_PROVIDER / LLM_MODEL + the user's
API key). Full ADK function-calling is preserved across all three so the agent
scanner's tool loop works unchanged.
"""
from __future__ import annotations

import os
import json
import logging
from typing import AsyncGenerator, Optional

import httpx
from pydantic import ConfigDict

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

import llm_providers

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 120
_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"


class PluggableLlm(BaseLlm):
    """ADK BaseLlm routed to the user's configured provider (OpenAI/Anthropic/Gemini)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    model: str = "gemini-2.5-flash"
    provider: str = "gemini"
    request_timeout: int = _REQUEST_TIMEOUT

    @classmethod
    def supported_models(cls) -> list[str]:
        return [r"pluggable/.*"]

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        provider = (self.provider or llm_providers.get_provider()).lower()
        try:
            if provider == "gemini":
                content = await self._gemini(llm_request)
            elif provider == "openai":
                content = await self._openai(llm_request)
            elif provider == "anthropic":
                content = await self._anthropic(llm_request)
            else:
                yield LlmResponse(error_code="400",
                                  error_message=f"Unsupported LLM provider '{provider}'")
                return
        except llm_providers.LLMNotConfigured as exc:
            yield LlmResponse(error_code="401", error_message=str(exc))
            return
        except Exception as exc:  # noqa: BLE001 — surface as ADK error response
            logger.exception("PluggableLlm (%s) failed", provider)
            yield LlmResponse(error_code="502", error_message=f"{provider} call failed: {exc}")
            return

        if content is None:
            yield LlmResponse(error_code="500", error_message="Empty/unparseable LLM response")
            return
        yield LlmResponse(content=content)

    # ── Gemini (Google GenAI public API) ──────────────────────────────────────
    async def _gemini(self, req: LlmRequest) -> Optional[types.Content]:
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key:
            raise llm_providers.LLMNotConfigured("GEMINI_API_KEY not set")

        payload: dict = {"contents": [c.model_dump(exclude_none=True, by_alias=True)
                                      for c in req.contents]}
        cfg = req.config
        if cfg and cfg.system_instruction:
            si = cfg.system_instruction
            payload["systemInstruction"] = (
                {"parts": [{"text": si}]} if isinstance(si, str)
                else si.model_dump(exclude_none=True, by_alias=True)
            )
        if cfg and cfg.tools:
            tools = [t.model_dump(exclude_none=True, by_alias=True)
                    if isinstance(t, types.Tool) else t for t in cfg.tools]
            payload["tools"] = [self._normalize_tool(t) for t in tools]
        if cfg and cfg.tool_config:
            tc = cfg.tool_config
            payload["toolConfig"] = (tc.model_dump(exclude_none=True, by_alias=True)
                                     if isinstance(tc, types.ToolConfig) else tc)
        gen: dict = {"temperature": getattr(cfg, "temperature", None) or 0.5,
                     "maxOutputTokens": getattr(cfg, "max_output_tokens", None) or 2048}
        payload["generationConfig"] = gen

        url = f"{_GEMINI_BASE}/models/{self.model}:generateContent?key={key}"
        async with httpx.AsyncClient(timeout=self.request_timeout) as client:
            resp = await client.post(url, json=payload,
                                     headers={"Content-Type": "application/json"})
        if resp.status_code != 200:
            raise Exception(f"Gemini HTTP {resp.status_code}: {resp.text[:300]}")
        return self._parse_gemini(resp.json())

    @staticmethod
    def _normalize_tool(tool: dict) -> dict:
        """The google-adk/google-genai SDKs may emit function declarations using
        the newer `parametersJsonSchema` key (JSON_SCHEMA_FOR_FUNC_DECL feature).
        The `v1` REST generateContent endpoint only accepts the OpenAPI-schema
        `parameters` key, so rename it back before sending."""
        fdecls = tool.get("functionDeclarations") or tool.get("function_declarations")
        if not fdecls:
            return tool
        for fd in fdecls:
            if "parametersJsonSchema" in fd:
                fd["parameters"] = fd.pop("parametersJsonSchema")
            if "parameters_json_schema" in fd:
                fd["parameters"] = fd.pop("parameters_json_schema")
        return tool

    @staticmethod
    def _parse_gemini(data: dict) -> Optional[types.Content]:
        cands = data.get("candidates")
        if not cands:
            return None
        raw = cands[0].get("content") or {}
        parts: list[types.Part] = []
        for p in raw.get("parts", []):
            if "text" in p and not p.get("thought"):
                parts.append(types.Part.from_text(text=p["text"]))
            elif "functionCall" in p:
                fc = p["functionCall"]
                parts.append(types.Part(function_call=types.FunctionCall(
                    name=fc.get("name", ""), args=fc.get("args", {}))))
        return types.Content(role=raw.get("role", "model"), parts=parts) if parts else None

    # ── Shared: ADK contents → role/text/tool extraction ─────────────────────
    @staticmethod
    def _iter_parts(req: LlmRequest):
        for c in req.contents:
            yield c.role or "user", (c.parts or [])

    @staticmethod
    def _tool_decls(req: LlmRequest) -> list[dict]:
        decls = []
        cfg = req.config
        for tool in (cfg.tools if cfg and cfg.tools else []):
            t = tool.model_dump(exclude_none=True, by_alias=True) if isinstance(tool, types.Tool) else tool
            for fd in t.get("functionDeclarations", []) or t.get("function_declarations", []):
                decls.append(PluggableLlm._normalize_tool({"functionDeclarations": [fd]})["functionDeclarations"][0])
        return decls

    @staticmethod
    def _system_text(req: LlmRequest) -> Optional[str]:
        cfg = req.config
        if cfg and cfg.system_instruction:
            si = cfg.system_instruction
            if isinstance(si, str):
                return si
            if isinstance(si, types.Content):
                return "".join(p.text for p in (si.parts or []) if getattr(p, "text", None))
        return None

    # ── OpenAI (official SDK, chat.completions + tools) ───────────────────────
    async def _openai(self, req: LlmRequest) -> Optional[types.Content]:
        from openai import AsyncOpenAI
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise llm_providers.LLMNotConfigured("OPENAI_API_KEY not set")
        client = AsyncOpenAI(api_key=key)

        messages = []
        if (sys := self._system_text(req)):
            messages.append({"role": "system", "content": sys})
        for role, parts in self._iter_parts(req):
            text = "".join(p.text for p in parts if getattr(p, "text", None))
            fcs = [p.function_call for p in parts if getattr(p, "function_call", None)]
            frs = [p.function_response for p in parts if getattr(p, "function_response", None)]
            if fcs:
                messages.append({"role": "assistant", "content": text or None,
                    "tool_calls": [{"id": fc.name, "type": "function",
                                    "function": {"name": fc.name, "arguments": json.dumps(fc.args or {})}}
                                   for fc in fcs]})
            elif frs:
                for fr in frs:
                    messages.append({"role": "tool", "tool_call_id": fr.name,
                                     "content": json.dumps(fr.response or {})})
            elif text:
                messages.append({"role": "assistant" if role == "model" else "user", "content": text})

        tools = [{"type": "function", "function": {
            "name": d.get("name"), "description": d.get("description", ""),
            "parameters": d.get("parameters", {"type": "object", "properties": {}})}}
            for d in self._tool_decls(req)]

        resp = await client.chat.completions.create(
            model=self.model, messages=messages,
            tools=tools or None, temperature=0.5, max_tokens=2048)
        msg = resp.choices[0].message
        parts: list[types.Part] = []
        if msg.content:
            parts.append(types.Part.from_text(text=msg.content))
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            parts.append(types.Part(function_call=types.FunctionCall(name=tc.function.name, args=args)))
        return types.Content(role="model", parts=parts) if parts else None

    # ── Anthropic (official SDK, messages + tools) ────────────────────────────
    async def _anthropic(self, req: LlmRequest) -> Optional[types.Content]:
        from anthropic import AsyncAnthropic
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise llm_providers.LLMNotConfigured("ANTHROPIC_API_KEY not set")
        client = AsyncAnthropic(api_key=key)

        messages = []
        for role, parts in self._iter_parts(req):
            text = "".join(p.text for p in parts if getattr(p, "text", None))
            fcs = [p.function_call for p in parts if getattr(p, "function_call", None)]
            frs = [p.function_response for p in parts if getattr(p, "function_response", None)]
            if fcs:
                blocks = ([{"type": "text", "text": text}] if text else []) + [
                    {"type": "tool_use", "id": fc.name, "name": fc.name, "input": fc.args or {}}
                    for fc in fcs]
                messages.append({"role": "assistant", "content": blocks})
            elif frs:
                messages.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": fr.name, "content": json.dumps(fr.response or {})}
                    for fr in frs]})
            elif text:
                messages.append({"role": "assistant" if role == "model" else "user", "content": text})

        tools = [{"name": d.get("name"), "description": d.get("description", ""),
                  "input_schema": d.get("parameters", {"type": "object", "properties": {}})}
                 for d in self._tool_decls(req)]

        kwargs = {"model": self.model, "max_tokens": 2048, "temperature": 0.5, "messages": messages}
        if (sys := self._system_text(req)):
            kwargs["system"] = sys
        if tools:
            kwargs["tools"] = tools
        resp = await client.messages.create(**kwargs)

        parts: list[types.Part] = []
        for block in resp.content:
            if block.type == "text":
                parts.append(types.Part.from_text(text=block.text))
            elif block.type == "tool_use":
                parts.append(types.Part(function_call=types.FunctionCall(name=block.name, args=block.input or {})))
        return types.Content(role="model", parts=parts) if parts else None
