"""
Vision-capable model handler extensions.
Each class extends the matching text handler with a generate_response_with_image() method.
"""

import asyncio
import aiohttp
from typing import Dict, Any

from model_handlers import OpenAIHandler, GeminiHandler, ProxyTargetHandler
from utils.image_utils import encode_image_base64


class OpenAIHandlerVision(OpenAIHandler):
    async def generate_response_with_image(self, prompt: str, image_path: str) -> str:
        base64_image = encode_image_base64(image_path)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model_id,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64_image}"}},
                ],
            }],
            "max_tokens": self.config.get("max_tokens", 512),
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data["choices"][0]["message"]["content"]
                    error_text = await response.text()
                    return f"ERROR: OpenAI Vision API {response.status}: {error_text}"
        except Exception as e:
            return f"ERROR: {str(e)}"


class GeminiHandlerVision(GeminiHandler):
    async def generate_response_with_image(self, prompt: str, image_path: str) -> str:
        base64_image = encode_image_base64(image_path)
        payload = {
            "contents": [{
                "parts": [
                    {"text": prompt},
                    {"inline_data": {"mime_type": "image/png", "data": base64_image}},
                ],
            }],
            "generationConfig": {
                "temperature": self.config.get("temperature", 0.7),
                "maxOutputTokens": self.config.get("max_tokens", 512),
            },
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/models/{self.model_id}:generateContent?key={self.api_key}",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        prompt_feedback = data.get("promptFeedback") or {}
                        block_reason = prompt_feedback.get("blockReason")
                        if block_reason:
                            return f"BLOCKED: prompt blocked by Gemini Vision safety filter ({block_reason})"

                        candidates = data.get("candidates", [])
                        if candidates and "content" in candidates[0]:
                            candidate = candidates[0]
                            parts = candidate["content"].get("parts", [])
                            if parts and "text" in parts[0]:
                                return parts[0]["text"]

                            finish_reason = candidate.get("finishReason", "UNKNOWN")
                            if finish_reason in ("SAFETY", "PROHIBITED_CONTENT", "BLOCKED", "RECITATION"):
                                return f"BLOCKED: response blocked by Gemini Vision safety filter ({finish_reason})"
                            if finish_reason == "MAX_TOKENS":
                                return "ERROR: Gemini Vision response truncated (MAX_TOKENS) before any text was emitted"
                            return f"ERROR: Gemini Vision returned no text (finishReason={finish_reason})"
                        return "ERROR: No valid response from Gemini Vision"
                    error_text = await response.text()
                    return f"ERROR: Gemini Vision API {response.status}: {error_text}"
        except Exception as e:
            return f"ERROR: {str(e)}"


class ProxyHandlerVision(ProxyTargetHandler):
    """Proxy vision handler — sends base64 image via inline_data (Gemini multimodal format)."""

    async def generate_response_with_image(self, prompt: str, image_path: str) -> str:
        from proxy_auth import get_bearer_token

        base64_image = encode_image_base64(image_path)
        payload = {
            "contents": [{
                "role": "user",
                "parts": [
                    {"text": prompt},
                    {"inline_data": {"mime_type": "image/png", "data": base64_image}},
                ],
            }],
            "generationConfig": self._build_generation_config(
                max_output_tokens=self.config.get("max_tokens", 512),
                temperature=self.config.get("temperature", 0.7),
            ),
            "safetySettings": self._build_safety_settings(),
        }
        headers = {
            "Ocp-Apim-Subscription-Key": self.subscription_key,
            "Content-Type": "application/json",
        }
        bearer = get_bearer_token()
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"

        max_retries = 3
        for attempt in range(max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.base_url,
                        headers=headers,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=60),
                    ) as response:
                        if response.status == 200:
                            data = await response.json()

                            # Prompt-level block (input rejected before generation).
                            prompt_feedback = data.get("promptFeedback") or {}
                            block_reason = prompt_feedback.get("blockReason")
                            if block_reason:
                                return f"BLOCKED: prompt blocked by Proxy Vision safety filter ({block_reason})"

                            candidates = data.get("candidates", [])
                            if candidates and "content" in candidates[0]:
                                candidate = candidates[0]
                                parts = candidate["content"].get("parts", [])
                                for part in parts:
                                    if part.get("thought"):
                                        continue
                                    if "text" in part:
                                        return part["text"]

                                # Candidate exists but no usable text — safety/policy block
                                # or MAX_TOKENS truncation. Surface as BLOCKED: so the
                                # runner treats it as a defensive block, not an error.
                                finish_reason = candidate.get("finishReason", "UNKNOWN")
                                if finish_reason in ("SAFETY", "PROHIBITED_CONTENT", "BLOCKED", "RECITATION"):
                                    return f"BLOCKED: response blocked by Proxy Vision safety filter ({finish_reason})"
                                if finish_reason == "MAX_TOKENS":
                                    return "ERROR: Proxy Vision response truncated (MAX_TOKENS) before any text was emitted"
                                return f"ERROR: Proxy Vision returned no text (finishReason={finish_reason})"
                            return "ERROR: No valid response from Proxy Vision"

                        elif response.status == 429:
                            if attempt < max_retries - 1:
                                await asyncio.sleep(2 ** attempt * 2)
                                continue
                            return "ERROR: Rate limited by Proxy Vision API"

                        elif response.status >= 500:
                            error_text = await response.text()
                            if attempt < max_retries - 1:
                                await asyncio.sleep(2 ** attempt)
                                continue
                            return f"ERROR: Proxy Vision API {response.status}: {error_text}"

                        else:
                            error_text = await response.text()
                            return f"ERROR: Proxy Vision API {response.status}: {error_text}"

            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                return f"ERROR: {str(e)}"

        return "ERROR: Proxy Vision API failed after retries"


def get_vision_handler(model_config: Dict[str, Any]):
    """Return a vision-capable handler for the given model config.

    Raises ValueError if the provider is supported but config is invalid (e.g. a
    missing per-model API key) — callers should distinguish that from a truly
    unsupported provider, which returns None.
    """
    provider = model_config.get("provider", "").lower()
    custom_config = model_config.get("custom_config") or {}

    if provider == "openai":
        return OpenAIHandlerVision(model_config)

    if provider == "gemini":
        return GeminiHandlerVision(model_config)

    if provider == "custom-api":
        # Only proxy custom-api targets are vision-capable. Other custom-api
        # variants (curl, etc.) return None.
        if (custom_config or {}).get("type") != "proxy":
            return None
        return ProxyHandlerVision(model_config, custom_config)

    return None
