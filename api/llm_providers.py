"""
Multi-provider LLM abstraction for Triksha (open-source edition).

Direct calls to the public
LLM providers the user configures with their own API keys:

    - OpenAI       (gpt-4o, gpt-4o-mini, ...)
    - Anthropic    (claude-* )
    - Google Gemini (gemini-* )

Configuration is read from environment / the local setup store:
    LLM_PROVIDER      one of: openai | anthropic | gemini   (default: gemini)
    LLM_MODEL         provider-specific model id            (sensible default per provider)
    OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY     user-supplied keys

The single public entry point is `complete()`, which all feature code reaches
through the compatibility shim in llm_client.APILLMClient. Core feature
logic is unchanged — only the transport/auth swaps.
"""
from __future__ import annotations

import os
import json
import asyncio
import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Defaults ────────────────────────────────────────────────────────────────
_DEFAULT_MODELS = {
    "openai":    "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-6",
    "gemini":    "gemini-2.5-flash",
}
_TIMEOUT = 90


def get_provider() -> str:
    return (os.environ.get("LLM_PROVIDER") or "gemini").strip().lower()


def get_model(provider: Optional[str] = None) -> str:
    provider = provider or get_provider()
    return os.environ.get("LLM_MODEL") or _DEFAULT_MODELS.get(provider, "gemini-2.5-flash")


def _api_key(provider: str) -> Optional[str]:
    return {
        "openai":    os.environ.get("OPENAI_API_KEY"),
        "anthropic": os.environ.get("ANTHROPIC_API_KEY"),
        "gemini":    os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"),
    }.get(provider)


class LLMNotConfigured(RuntimeError):
    """Raised when no provider API key is available."""


# ── Provider implementations (raw HTTP, no heavy SDK deps) ────────────────────
def _openai_complete(prompt: str, system: Optional[str], temperature: float,
                     max_tokens: int, model: str, key: str) -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={"model": model, "messages": messages,
              "temperature": temperature, "max_tokens": max_tokens},
        timeout=_TIMEOUT,
    )
    if resp.status_code != 200:
        raise Exception(f"OpenAI error {resp.status_code}: {resp.text[:300]}")
    return resp.json()["choices"][0]["message"]["content"].strip()


def _anthropic_complete(prompt: str, system: Optional[str], temperature: float,
                        max_tokens: int, model: str, key: str) -> str:
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "Content-Type": "application/json"},
        json=body,
        timeout=_TIMEOUT,
    )
    if resp.status_code != 200:
        raise Exception(f"Anthropic error {resp.status_code}: {resp.text[:300]}")
    parts = resp.json().get("content", [])
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()


def _gemini_complete(prompt: str, system: Optional[str], temperature: float,
                     max_tokens: int, model: str, key: str) -> str:
    proxy_base = os.environ.get("LLM_PROXY_BASE_URL", "").rstrip("/")
    if proxy_base:
        url = f"{proxy_base}/{model}/:generateContent"
        headers = {
            "Ocp-Apim-Subscription-Key": key,
            "Content-Type": "application/json",
        }
    else:
        url = f"https://generativelanguage.googleapis.com/v1/models/{model}:generateContent?key={key}"
        headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature, "topP": 0.8},
    }
    if system:
        payload["systemInstruction"] = {"parts": [{"text": system}]}
    print(f"[Gemini DEBUG] url={url.split('?')[0]} model={model} proxy={bool(proxy_base)}", flush=True)
    resp = requests.post(url, json=payload, headers=headers, timeout=_TIMEOUT)
    if resp.status_code != 200:
        raise Exception(f"Gemini error {resp.status_code}: {resp.text[:300]}")
    cands = resp.json().get("candidates") or []
    if not cands:
        raise Exception("Gemini returned no candidates")
    parts = (cands[0].get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts if "text" in p and not p.get("thought")).strip()
    if not text:
        raise Exception("Gemini returned empty content")
    return text


_DISPATCH = {
    "openai":    _openai_complete,
    "anthropic": _anthropic_complete,
    "gemini":    _gemini_complete,
}


def complete_sync(prompt: str, *, system: Optional[str] = None,
                  temperature: float = 0.4, max_tokens: int = 1000,
                  provider: Optional[str] = None, model: Optional[str] = None) -> str:
    """Blocking completion. Routes to the configured provider with the user's key."""
    provider = (provider or get_provider()).lower()
    model = model or get_model(provider)
    key = _api_key(provider)
    if not key:
        raise LLMNotConfigured(
            f"No API key configured for provider '{provider}'. "
            f"Set it in Settings or the {provider.upper()}_API_KEY env var."
        )
    fn = _DISPATCH.get(provider)
    if not fn:
        raise LLMNotConfigured(f"Unsupported LLM provider '{provider}'. "
                               f"Choose one of: {', '.join(_DISPATCH)}")
    return fn(prompt, system, temperature, max_tokens, model, key)


async def complete(prompt: str, *, system: Optional[str] = None,
                   temperature: float = 0.4, max_tokens: int = 1000,
                   provider: Optional[str] = None, model: Optional[str] = None) -> str:
    """Async wrapper — runs the blocking provider call in a thread."""
    return await asyncio.to_thread(
        complete_sync, prompt, system=system, temperature=temperature,
        max_tokens=max_tokens, provider=provider, model=model,
    )


def is_configured(provider: Optional[str] = None) -> bool:
    return bool(_api_key((provider or get_provider()).lower()))


# ── ADK model factory (for the agent scanner) ────────────────────────────────
# The autonomous agent scanner runs on Google ADK and needs FUNCTION-CALLING,
# which the text-only complete() above does not cover. We use a first-party
# PluggableLlm (BaseLlm) driven through each provider's official SDK/API — more
# robust than a generic wrapper — as the plug-and-play replacement for the
# Proxy-backed ProxyLlm adapter.
def get_adk_model(provider: Optional[str] = None, model: Optional[str] = None):
    """Return an ADK BaseLlm for the configured provider, using the user's key."""
    provider = (provider or get_provider()).lower()
    model = model or get_model(provider)
    key = _api_key(provider)
    if not key:
        raise LLMNotConfigured(
            f"No API key configured for provider '{provider}'. "
            f"Add it in Settings or set {provider.upper()}_API_KEY."
        )
    if provider not in ("openai", "anthropic", "gemini"):
        raise LLMNotConfigured(f"Unsupported LLM provider '{provider}' for the agent scanner.")

    from pluggable_llm import PluggableLlm
    return PluggableLlm(provider=provider, model=model)
