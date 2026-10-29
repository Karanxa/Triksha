"""
Standalone model handlers for the API - independent of CLI components.
"""

import asyncio
import aiohttp
import json
import os
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from rich.console import Console

from env_loader import get_api_key


class BaseModelHandler(ABC):
    """Base class for model handlers"""
    
    def __init__(self, model_config: Dict[str, Any]):
        """Initialize model handler"""
        self.config = model_config
        self.console = Console()
        self.provider = model_config.get("provider")
        self.model_id = model_config.get("model_id")
    
    @abstractmethod
    async def generate_response(self, prompt: str) -> str:
        """Generate response from the model"""
        pass


class OpenAIHandler(BaseModelHandler):
    """Handler for OpenAI models"""
    
    def __init__(self, model_config: Dict[str, Any]):
        super().__init__(model_config)
        self.api_key = model_config.get("api_key") or get_api_key("openai")
        self.base_url = "https://api.openai.com/v1"
        
        if not self.api_key:
            raise ValueError("OpenAI API key is required")
    
    async def generate_response(self, prompt: str) -> str:
        """Generate response using OpenAI API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model_id,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.config.get("max_tokens", 512),
            "temperature": self.config.get("temperature", 0.7)
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data["choices"][0]["message"]["content"]
                    else:
                        error_text = await response.text()
                        return f"ERROR: OpenAI API error {response.status}: {error_text}"
        
        except Exception as e:
            return f"ERROR: OpenAI request failed: {str(e)}"


class GeminiHandler(BaseModelHandler):
    """Handler for Google Gemini models.

    When LLM_PROXY_BASE_URL is set the request is routed through the proxy
    (subscription-key auth).  Otherwise it calls the public Google API
    directly (AIza* key required).
    """

    def __init__(self, model_config: Dict[str, Any]):
        super().__init__(model_config)
        # model_id may live at top-level or nested inside custom_config
        if not self.model_id:
            self.model_id = (model_config.get("custom_config") or {}).get("model_id") or "gemini-1.5-flash"
        self.api_key = model_config.get("api_key") or get_api_key("gemini")
        proxy_base = os.getenv("LLM_PROXY_BASE_URL", "").rstrip("/")
        if proxy_base:
            self.base_url = f"{proxy_base}/{self.model_id}/:generateContent"
            self._use_proxy = True
        else:
            self.base_url = "https://generativelanguage.googleapis.com/v1"
            self._use_proxy = False

        if not self.api_key:
            raise ValueError("Gemini API key is required")

    async def generate_response(self, prompt: str) -> str:
        """Generate response using Gemini API (direct or via proxy)."""
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.config.get("temperature", 0.7),
                "maxOutputTokens": self.config.get("max_tokens", 512),
            },
        }

        try:
            async with aiohttp.ClientSession() as session:
                if self._use_proxy:
                    headers = {
                        "Ocp-Apim-Subscription-Key": self.api_key,
                        "Content-Type": "application/json",
                    }
                    url = self.base_url
                    resp = await session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=60))
                else:
                    url = f"{self.base_url}/models/{self.model_id}:generateContent?key={self.api_key}"
                    resp = await session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=30))

                async with resp:
                    if resp.status == 200:
                        data = await resp.json()
                        candidates = data.get("candidates", [])
                        if candidates and "content" in candidates[0]:
                            parts = candidates[0]["content"].get("parts", [])
                            if parts:
                                return parts[0].get("text", "No response text")
                        return "ERROR: No valid response from Gemini"
                    else:
                        error_text = await resp.text()
                        return f"ERROR: Gemini API error {resp.status}: {error_text}"

        except Exception as e:
            return f"ERROR: Gemini request failed: {str(e)}"



class AnthropicHandler(BaseModelHandler):
    """Handler for Anthropic Claude models"""

    def __init__(self, model_config: Dict[str, Any]):
        super().__init__(model_config)
        self.api_key = model_config.get("api_key") or get_api_key("anthropic")
        if not self.api_key:
            raise ValueError("Anthropic API key is required")

    async def generate_response(self, prompt: str) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model_id,
            "max_tokens": self.config.get("max_tokens", 512),
            "messages": [{"role": "user", "content": prompt}],
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = data.get("content", [])
                        return content[0].get("text", "No response text") if content else "ERROR: empty Anthropic response"
                    else:
                        error_text = await response.text()
                        return f"ERROR: Anthropic API error {response.status}: {error_text}"
        except Exception as e:
            return f"ERROR: Anthropic request failed: {str(e)}"


class SelfHostedHandler(BaseModelHandler):
    """Handler for self-hosted / OpenAI-compatible endpoints"""

    def __init__(self, model_config: Dict[str, Any]):
        super().__init__(model_config)
        custom_config = model_config.get("custom_config", {})
        self.base_url = (custom_config.get("base_url") or "").rstrip("/")
        self.api_key = model_config.get("api_key") or custom_config.get("api_key") or "none"
        if not self.base_url:
            raise ValueError("Self-hosted provider requires a base_url in custom_config")

    async def generate_response(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model_id or "default",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.config.get("max_tokens", 512),
            "temperature": self.config.get("temperature", 0.7),
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data["choices"][0]["message"]["content"]
                    else:
                        error_text = await response.text()
                        return f"ERROR: Self-hosted API error {response.status}: {error_text}"
        except Exception as e:
            return f"ERROR: Self-hosted request failed: {str(e)}"


class CustomAPIHandler(BaseModelHandler):
    """Handler for custom API models"""
    
    def __init__(self, model_config: Dict[str, Any]):
        super().__init__(model_config)
        self.endpoint_url = model_config.get("endpoint_url")
        self.headers = model_config.get("headers", {})
        self.payload_template = model_config.get("payload_template", {})
        self.response_mapping = model_config.get("response_mapping", {})
        
        if not self.endpoint_url:
            raise ValueError("Custom API endpoint URL is required")
    
    async def generate_response(self, prompt: str) -> str:
        """Generate response using custom API"""
        # Prepare payload by substituting prompt
        payload = self._prepare_payload(prompt)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.endpoint_url,
                    headers=self.headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._extract_response(data)
                    else:
                        error_text = await response.text()
                        return f"ERROR: Custom API error {response.status}: {error_text}"
        
        except Exception as e:
            return f"ERROR: Custom API request failed: {str(e)}"
    
    def _prepare_payload(self, prompt: str) -> Dict[str, Any]:
        """Prepare payload by substituting prompt into template"""
        payload = json.loads(json.dumps(self.payload_template))  # Deep copy
        
        # Recursively replace {prompt} placeholders
        def replace_prompt(obj):
            if isinstance(obj, str):
                return obj.replace("{prompt}", prompt)
            elif isinstance(obj, dict):
                return {k: replace_prompt(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_prompt(item) for item in obj]
            return obj
        
        return replace_prompt(payload)
    
    def _extract_response(self, data: Dict[str, Any]) -> str:
        """Extract response from API response using mapping"""
        if not self.response_mapping or "content" not in self.response_mapping:
            # Try common response fields
            possible_fields = ["response", "text", "content", "message", "output"]
            for field in possible_fields:
                if field in data:
                    return str(data[field])
            return str(data)  # Return entire response as string
        
        # Use configured mapping
        path = self.response_mapping["content"]
        
        try:
            # Navigate nested dictionary using dot notation
            result = data
            for key in path.split("."):
                if key.isdigit():
                    result = result[int(key)]
                else:
                    result = result[key]
            return str(result)
        
        except (KeyError, IndexError, TypeError):
            return f"ERROR: Could not extract response using mapping: {path}"


class HuggingFaceHandler(BaseModelHandler):
    """Handler for HuggingFace Inference API models"""
    
    def __init__(self, model_config: Dict[str, Any]):
        super().__init__(model_config)
        self.api_key = model_config.get("api_key") or get_api_key("huggingface")
        self.base_url = "https://api-inference.huggingface.co/models"
        
        if not self.api_key:
            raise ValueError("HuggingFace API key is required")
    
    async def generate_response(self, prompt: str) -> str:
        """Generate response using HuggingFace Inference API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": self.config.get("max_tokens", 512),
                "temperature": self.config.get("temperature", 0.7),
                "return_full_text": False
            }
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/{self.model_id}",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if isinstance(data, list) and len(data) > 0:
                            return data[0].get("generated_text", "No response from HuggingFace")
                        return str(data)
                    else:
                        error_text = await response.text()
                        return f"ERROR: HuggingFace API error {response.status}: {error_text}"
        
        except Exception as e:
            return f"ERROR: HuggingFace request failed: {str(e)}"


class CustomCurlHandler(BaseModelHandler):
    """Handler for custom models using curl commands (matches CLI custom model registration)"""
    
    def __init__(self, model_config: Dict[str, Any], custom_config: Dict[str, Any]):
        super().__init__(model_config)
        self.curl_command = custom_config.get("curl_command")
        self.prompt_placeholder = custom_config.get("prompt_placeholder", "{prompt}")
        self.response_extraction_field = custom_config.get("response_extraction_field")
        
        if not self.curl_command:
            raise ValueError("curl_command is required for custom-curl models")
    
    async def generate_response(self, prompt: str) -> str:
        """Generate response using curl command with universal shell script approach"""
        try:
            import subprocess
            import json
            import tempfile
            import os
            
            # Universal approach: prepare command (returns shell script execution command)
            script_cmd = self._prepare_curl_command(prompt)
            
            # Execute the shell script directly - no parsing issues
            process = subprocess.run(
                script_cmd.split(),  # "/bin/bash /path/to/script.sh"
                capture_output=True,
                timeout=30,
                check=False,
                text=True
            )
            
            if process.returncode != 0:
                return f"ERROR: Curl command failed with code {process.returncode}: {process.stderr}"
            
            response_text = process.stdout.strip()
            
            # Try to parse as JSON and extract the specified field
            if self.response_extraction_field:
                try:
                    response_json = json.loads(response_text)
                    extracted_text = self._extract_response_field(response_json, self.response_extraction_field)
                    if extracted_text:
                        return extracted_text
                except json.JSONDecodeError:
                    pass  # Fall back to raw text
            
            # Try common response formats
            try:
                response_json = json.loads(response_text)
                
                # Check OpenAI-like format
                if "choices" in response_json and response_json["choices"]:
                    choice = response_json["choices"][0]
                    if "message" in choice and "content" in choice["message"]:
                        return choice["message"]["content"]
                    elif "text" in choice:
                        return choice["text"]
                
                # Check other common formats
                if "content" in response_json:
                    return response_json["content"]
                elif "text" in response_json:
                    return response_json["text"]
                elif "response" in response_json:
                    return response_json["response"]
                
            except json.JSONDecodeError:
                # If not JSON, return raw text
                return response_text
            
            # If we couldn't extract anything meaningful, return raw response
            return response_text if response_text else "ERROR: Empty response from API"
            
        except Exception as e:
            return f"ERROR: Custom curl request failed: {str(e)}"
        finally:
            # Clean up any temporary files
            self._cleanup_temp_files()
    
    def _prepare_curl_command(self, prompt: str) -> str:
        """Universal curl command preparation - always uses shell script approach"""
        return self._universal_shell_script_approach(prompt)
    
    def _universal_shell_script_approach(self, prompt: str) -> str:
        """Universal approach: write command to shell script with proper prompt substitution using heredoc"""
        import tempfile
        import os
        import shlex
        
        # Normalize the curl command: remove line breaks and extra whitespace
        normalized_cmd = ' '.join(self.curl_command.split())
        
        # Log for debugging
        self.console.print(f"[dim]Parsing curl command (length: {len(normalized_cmd)} chars)[/]")
        
        # Parse curl command using shlex (handles quotes and escapes properly)
        try:
            parts = shlex.split(normalized_cmd)
        except ValueError as e:
            self.console.print(f"[red]ERROR: Failed to parse curl command with shlex: {e}[/]")
            raise ValueError(f"Invalid curl command syntax: {e}")
        
        if not parts or parts[0] != 'curl':
            raise ValueError("Command must start with 'curl'")
        
        self.console.print(f"[dim]Parsed into {len(parts)} parts[/]")
        
        # Extract components by iterating through arguments
        url = None
        headers = []
        data = None
        method = 'POST'
        
        i = 1  # Start after 'curl'
        while i < len(parts):
            arg = parts[i]
            
            # Method flag
            if arg in ['-X', '--request']:
                if i + 1 < len(parts):
                    method = parts[i + 1]
                    i += 2
                    continue
                else:
                    i += 1
                    continue
            
            # Header flag
            elif arg in ['-H', '--header']:
                if i + 1 < len(parts):
                    headers.append(parts[i + 1])
                    i += 2
                    continue
                else:
                    i += 1
                    continue
            
            # Data flag
            elif arg in ['-d', '--data', '--data-raw', '--data-binary', '--data-urlencode']:
                if i + 1 < len(parts):
                    data = parts[i + 1]
                    i += 2
                    continue
                else:
                    i += 1
                    continue
            
            # Flags without values
            elif arg in ['--location', '-L', '--compressed', '--insecure', '-k']:
                i += 1
                continue
            
            # Non-flag argument = likely the URL
            elif not arg.startswith('-'):
                # URL is the first non-flag argument we encounter
                if url is None:
                    url = arg
                i += 1
                continue
            
            # Unknown flag - skip it
            else:
                i += 1
                continue
        
        # Validate required components
        if not url:
            self.console.print(f"[red]ERROR: No URL found in curl command[/]")
            self.console.print(f"[yellow]Hint: Parsed {len(parts)} parts, but none matched URL pattern[/]")
            # Show first few non-flag args for debugging
            non_flags = [p for p in parts[1:] if not p.startswith('-')]
            self.console.print(f"[dim]Non-flag arguments found: {non_flags[:5]}[/]")
            raise ValueError("Could not parse URL from curl command")
        
        if not data:
            self.console.print(f"[red]ERROR: No data payload found in curl command[/]")
            self.console.print(f"[yellow]Hint: Use -d or --data flag with the JSON payload[/]")
            raise ValueError("Could not parse data from curl command")
        
        # Validate and clean URL
        from urllib.parse import urlparse
        
        url = url.strip()
        
        # CRITICAL FIX: Remove any embedded spaces from URL (caused by line breaks in original command)
        # This is safe because URLs should never have literal spaces
        url = url.replace(' ', '')
        
        # Check if URL is valid
        if not url.startswith('http://') and not url.startswith('https://'):
            self.console.print(f"[red]ERROR: URL must start with http:// or https://[/]")
            self.console.print(f"[dim]Got: {url[:100]}[/]")
            raise ValueError(f"Invalid URL format: {url[:100]}")
        
        # Validate URL structure using urllib
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("URL missing scheme or host")
        except Exception as e:
            self.console.print(f"[red]ERROR: Invalid URL structure: {e}[/]")
            self.console.print(f"[dim]Full URL: {url}[/]")
            raise ValueError(f"Malformed URL: {e}")
        
        # Success logging (show full URL for debugging)
        self.console.print(f"[green]✓ Full URL: {url}[/]")
        self.console.print(f"[green]✓ Headers: {len(headers)}[/]")
        self.console.print(f"[green]✓ Data: {len(data)} chars[/]")
        self.console.print(f"[green]✓ Method: {method}[/]")
        
        data_template = data
        
        # Escape the prompt for JSON properly
        json_safe_prompt = prompt.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        
        # Replace the placeholder in the data template
        data_with_prompt = data_template.replace(self.prompt_placeholder, json_safe_prompt)
        
        # Create a shell script using heredoc for the data payload
        import uuid as _uuid
        heredoc_tag = f"EOFDATA_{_uuid.uuid4().hex}"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as script:
            script.write("#!/bin/bash\n")
            script.write("set -e\n")
            script.write("# Universal curl execution with heredoc\n\n")

            # Use shlex.quote for URL and headers to prevent shell injection
            script.write(f"curl --location {shlex.quote(url)} \\\n")
            for header in headers:
                script.write(f"  --header {shlex.quote(header)} \\\n")
            # Quoted heredoc tag prevents variable/command expansion inside the body
            script.write(f"  --data @- << '{heredoc_tag}'\n")
            script.write(data_with_prompt + "\n")
            script.write(f"{heredoc_tag}\n")
            
            script_path = script.name
        
        # Make executable
        os.chmod(script_path, 0o755)
        
        # Store for cleanup
        self._temp_files = getattr(self, '_temp_files', [])
        self._temp_files.append(script_path)
        
        # Return the script execution command
        return f"/bin/bash {script_path}"
    
    def _cleanup_temp_files(self):
        """Clean up temporary files"""
        import os
        
        if hasattr(self, '_temp_files'):
            for temp_file in self._temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)
                except Exception:
                    pass  # Ignore cleanup errors
            self._temp_files = []
    
    def _extract_response_field(self, data: Dict[str, Any], field_path: str) -> Optional[str]:
        """Extract field from nested dictionary using dot notation"""
        try:
            # Handle simple field names and array indices
            # e.g., "choices[0].message.content"
            import re
            
            # Split by dots but handle array indices
            parts = re.split(r'\.', field_path)
            current = data
            
            for part in parts:
                if '[' in part and ']' in part:
                    # Handle array access like "choices[0]"
                    field_name = part.split('[')[0]
                    index_str = part.split('[')[1].rstrip(']')
                    index = int(index_str)
                    current = current[field_name][index]
                else:
                    current = current[part]
            
            return str(current) if current is not None else None
            
        except (KeyError, IndexError, ValueError, TypeError):
            return None


_ENV_SUBSCRIPTION_KEYS = frozenset({"internal", "from_env"})


class ProxyTargetHandler(BaseModelHandler):
    """Handler for proxy target models using subscription key"""

    # Single source of truth — keep in sync with APILLMClient in llm_client.py.
    _MODEL_KEY_ENV: Dict[str, str] = {
        "gemini-2.5-flash": "GEMINI_API_KEY",
        "gemini-2.5-pro":   "GEMINI_API_KEY",
        "gemini-2.0-flash": "GEMINI_API_KEY",
        "gemini-1.5-pro":   "GEMINI_API_KEY",
        "gemini-1.5-flash": "GEMINI_API_KEY",
    }

    _SAFETY_CATEGORIES = [
        "HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_DANGEROUS_CONTENT",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "HARM_CATEGORY_HARASSMENT",
    ]

    # Static per-model payload config (mirrors APILLMClient._MODEL_PAYLOAD_CONFIG).
    _MODEL_PAYLOAD_CONFIG: Dict[str, dict] = {
        "gemini-2.5-flash": {
            "topP": 0.4,
            "topK": 32,
            "thinkingConfig": {"thinkingBudget": 0},
            "safetyThreshold": "BLOCK_MEDIUM_AND_ABOVE",
        },
        "gemini-2.5-pro": {
            "topP": 0.4,
            "topK": 32,
            "thinkingConfig": {"thinkingBudget": 0},
            "safetyThreshold": "BLOCK_MEDIUM_AND_ABOVE",
        },
        "gemini-2.0-flash": {
            "topP": 0.4,
            "topK": 32,
            "safetyThreshold": "BLOCK_MEDIUM_AND_ABOVE",
        },
        "gemini-1.5-pro": {
            "topP": 0.4,
            "safetyThreshold": "BLOCK_MEDIUM_AND_ABOVE",
        },
        "gemini-1.5-flash": {
            "topP": 0.4,
            "safetyThreshold": "BLOCK_MEDIUM_AND_ABOVE",
        },
    }

    def _build_generation_config(self, max_output_tokens: int, temperature: float) -> dict:
        model_cfg = self._MODEL_PAYLOAD_CONFIG.get(self.proxy_model_id, {})
        cfg: Dict[str, Any] = {
            "maxOutputTokens": max_output_tokens,
            "temperature": model_cfg.get("defaultTemperature", temperature),
            "topP": model_cfg.get("topP", 0.4),
        }
        if "topK" in model_cfg:
            cfg["topK"] = model_cfg["topK"]
        if "thinkingConfig" in model_cfg:
            cfg["thinkingConfig"] = model_cfg["thinkingConfig"]
        return cfg

    def _build_safety_settings(self) -> list:
        model_cfg = self._MODEL_PAYLOAD_CONFIG.get(self.proxy_model_id, {})
        threshold = model_cfg.get("safetyThreshold", "BLOCK_MEDIUM_AND_ABOVE")
        return [{"category": cat, "threshold": threshold} for cat in self._SAFETY_CATEGORIES]

    def __init__(self, model_config: Dict[str, Any], custom_config: Dict[str, Any]):
        super().__init__(model_config)

        self.proxy_model_id = custom_config.get("model_id", "gemini-2.5-flash")
        # scans route through llm_providers and never touch it.
        self.base_url = os.getenv("LLM_PROXY_BASE_URL", f"http://localhost:8080/{self.proxy_model_id}/:generateContent")

        # scans use the user-configured provider key (from Settings) and ignore it.
        model_key_env = self._MODEL_KEY_ENV.get(self.proxy_model_id, "GEMINI_API_KEY")
        custom_subscription_key = custom_config.get("subscription_key")
        self.is_playground = custom_subscription_key in _ENV_SUBSCRIPTION_KEYS
        if custom_subscription_key and custom_subscription_key not in _ENV_SUBSCRIPTION_KEYS:
            self.subscription_key = custom_subscription_key
        else:
            self.subscription_key = os.environ.get(model_key_env)
            if not self.subscription_key and self.proxy_model_id == "gemini-2.5-flash":
                self.subscription_key = os.environ.get("GEMINI_API_KEY")

    async def generate_response(self, prompt: str) -> str:
        """Run the prompt against the user-configured LLM provider.

        Safety refusals and empty responses are surfaced as BLOCKED: / ERROR:
        so verdict logic treats them as defensive (not a bypass).
        """
        import llm_providers

        if not llm_providers.is_configured():
            return "ERROR: No LLM provider API key configured. Set it in Settings."

        try:
            text = await llm_providers.complete(
                prompt,
                temperature=self.config.get("temperature", 0.7),
                max_tokens=self.config.get("max_tokens", 1000),
            )
            if text and text.strip():
                return text
            return "BLOCKED: provider returned no content (likely a safety refusal)"
        except llm_providers.LLMNotConfigured as e:
            return f"ERROR: {e}"
        except Exception as e:
            # Provider safety blocks typically surface as 'no candidates' /
            # 'empty content' — treat those as a defensive refusal.
            msg = str(e).lower()
            if "no candidates" in msg or "empty content" in msg or "safety" in msg or "blocked" in msg:
                return f"BLOCKED: response blocked by provider safety filter ({e})"
            return f"ERROR: LLM provider request failed: {e}"


class GuardrailHandler(BaseModelHandler):
    """Handler for Guardrail v1 evaluation service.

    Calls the safety-model predict endpoint directly (OpenAI-compatible chat
    completions format) and interprets the response as a guardrail verdict.
    """

    _DEFAULT_BASE_URL = os.getenv("GUARDRAIL_V1_BASE_URL", "")
    _DEFAULT_MODEL = "safety-v8-Meta-Llama-3-8B-Instruct"
    _DEFAULT_STOP = [
        "<pad>", "<unk>", "</s>", "<END>", "</s>",
        "<|im_end|>", "<unk>", "<|endoftext|>", "<eos>",
        "<end_of_turn>", "<|eot_id|>",
    ]

    # Retry configuration
    _MAX_RETRIES = 3
    _BASE_TIMEOUT = 120          # seconds
    _RETRY_BACKOFF_BASE = 2.0
    _RETRY_STATUSES = {502, 503, 504, 429}

    def __init__(self, model_config: Dict[str, Any], custom_config: Dict[str, Any]):
        super().__init__(model_config)
        self.base_url = custom_config.get("base_url", self._DEFAULT_BASE_URL).rstrip("/")
        self.model_name = custom_config.get("model", self._DEFAULT_MODEL)
        self.temperature = custom_config.get("temperature", 0.5)
        self.top_p = custom_config.get("top_p", 0.95)
        self.max_tokens = custom_config.get("max_tokens", 1000)
        self.frequency_penalty = custom_config.get("frequency_penalty", 0.0)
        self.stop_sequences = custom_config.get("stop", self._DEFAULT_STOP)

    async def generate_response(self, prompt: str) -> str:
        """Send prompt to the guardrail safety model and return the response."""
        payload = {
            "temperature": self.temperature,
            "top_p": self.top_p,
            "max_tokens": self.max_tokens,
            "stop": self.stop_sequences,
            "stream": False,
            "frequency_penalty": self.frequency_penalty,
            "model": self.model_name,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }

        headers = {
            "Content-Type": "application/json"
        }

        last_error: Optional[str] = None

        for attempt in range(1, self._MAX_RETRIES + 1):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.base_url}/predict",
                        json=payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self._BASE_TIMEOUT),
                    ) as response:
                        response_text = await response.text()

                        if response.status == 200:
                            return self._extract_response(response_text)
                        elif response.status in self._RETRY_STATUSES and attempt < self._MAX_RETRIES:
                            last_error = f"HTTP {response.status}"
                            wait = self._RETRY_BACKOFF_BASE ** (attempt - 1)
                            self.console.print(
                                f"[yellow]⚠ Guardrail returned {response.status}, retrying in {wait:.0f}s "
                                f"(attempt {attempt}/{self._MAX_RETRIES})...[/]"
                            )
                            await asyncio.sleep(wait)
                            continue
                        else:
                            return f"ERROR: Guardrail API error {response.status}: {response_text[:500]}"

            except asyncio.TimeoutError:
                last_error = f"Request timed out after {self._BASE_TIMEOUT}s"
                if attempt < self._MAX_RETRIES:
                    wait = self._RETRY_BACKOFF_BASE ** (attempt - 1)
                    self.console.print(
                        f"[yellow]⚠ Guardrail timeout ({self._BASE_TIMEOUT}s), retrying in {wait:.0f}s "
                        f"(attempt {attempt}/{self._MAX_RETRIES})...[/]"
                    )
                    await asyncio.sleep(wait)
                    continue

            except aiohttp.ClientError as e:
                last_error = f"{type(e).__name__}: {e}"
                if attempt < self._MAX_RETRIES:
                    wait = self._RETRY_BACKOFF_BASE ** (attempt - 1)
                    self.console.print(
                        f"[yellow]⚠ Guardrail connection error ({type(e).__name__}), retrying in {wait:.0f}s "
                        f"(attempt {attempt}/{self._MAX_RETRIES})...[/]"
                    )
                    await asyncio.sleep(wait)
                    continue

            except Exception as e:
                return f"ERROR: Guardrail request failed ({type(e).__name__}): {e}"

        # All retries exhausted
        return f"ERROR: Guardrail request failed after {self._MAX_RETRIES} attempts: {last_error}"

    def _extract_response(self, response_text: str) -> str:
        """Extract the guardrail verdict from the /predict endpoint output.

        Actual response format from the guardrail safety model:
          Blocked:  {"result":{"accept":false,"reason":"\"Indiscriminate Weapons\" detected by Safety LLM"},"stack_trace":"NA","server":"async"}
          Accepted: {"result":{"accept":true,"reason":null},"stack_trace":"NA","server":"async"}

        Returns:
          "BLOCKED: <reason>"  when result.accept is false  → _analyze_response_safety → is_refusal=True  → "Not Bypassed"
          "PASS: Accepted"     when result.accept is true   → _analyze_response_safety → is_refusal=False → "Bypassed"
        """
        try:
            data = json.loads(response_text)
        except json.JSONDecodeError:
            return response_text.strip() if response_text.strip() else "ERROR: Empty response from guardrail"

        if not isinstance(data, dict):
            return str(data)

        # ── Primary format: { "result": { "accept": bool, "reason": str|null } } ──
        result = data.get("result")
        if isinstance(result, dict) and "accept" in result:
            if result["accept"] is False:
                reason = result.get("reason") or "Blocked by guardrail safety model"
                return f"BLOCKED: {reason}"
            else:
                # accept=true → guardrail did NOT block → this counts as a bypass
                return "PASS: Accepted by guardrail safety model"

        # ── Fallback: top-level accept/blocked flags ──
        if data.get("accepted") is False or data.get("blocked") or data.get("rejected"):
            reason = data.get("reason", data.get("message", "Blocked by guardrail"))
            return f"BLOCKED: {reason}"

        return str(data)


class GuardrailV2Handler(GuardrailHandler):
    """Handler for Guardrail v2 - custom LLM-based guardrail on H100 compute.

    Same /predict endpoint and response format as GuardrailHandler; only the
    base URL and default model name differ.
    """

    _DEFAULT_BASE_URL = os.getenv("AEGIS_V2_BASE_URL", "")
    _DEFAULT_MODEL = "guardrail-v2-Meta-Llama-3-8B-Instruct"


class ModelArmorHandler(BaseModelHandler):
    """Handler for Google Cloud Model Armor guardrail.

    Calls the sanitizeUserPrompt endpoint and interprets filterMatchState:
      MATCH_FOUND   → BLOCKED (guardrail triggered)
      NO_MATCH_FOUND → PASS (prompt accepted)
    """

    _DEFAULT_LOCATION = "us-central1"
    _MAX_RETRIES = 3
    _BASE_TIMEOUT = 60
    _RETRY_BACKOFF_BASE = 2.0
    _RETRY_STATUSES = {502, 503, 504, 429}

    def __init__(self, model_config: Dict[str, Any], custom_config: Dict[str, Any]):
        super().__init__(model_config)
        # Strip whitespace/newlines — pasted form values commonly carry a trailing
        # space or newline, which malforms the URL path and yields a Google 404.
        self.project = str(custom_config.get("project", "") or "").strip()
        self.location = str(custom_config.get("location") or self._DEFAULT_LOCATION).strip()
        self.template = str(custom_config.get("template", "") or "").strip()
        self.bearer_token = str(custom_config.get("bearer_token", "") or "").strip()
        self._endpoint = (
            f"https://modelarmor.{self.location}.rep.googleapis.com/v1"
            f"/projects/{self.project}/locations/{self.location}"
            f"/templates/{self.template}:sanitizeUserPrompt"
        )
        if not (self.project and self.template and self.location):
            self.console.print(
                f"[red]⚠ Model Armor misconfigured — project='{self.project}' "
                f"location='{self.location}' template='{self.template}'[/]"
            )
        self.console.print(f"[dim]Model Armor endpoint: {self._endpoint}[/]")

    async def generate_response(self, prompt: str) -> str:
        """Call Model Armor sanitizeUserPrompt using `requests` (run in a thread).

        We use requests, not aiohttp, because aiohttp's ssl=False drops SNI and
        the request lands on Google's default vhost → generic HTML 404. requests
        (urllib3) always sends SNI and behaves exactly like the working curl,
        with verify toggling cleanly for the prod MITM-proxy case.
        """
        import asyncio
        import requests
        import urllib3

        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
        }
        payload = {"userPromptData": {"text": prompt}}
        last_error: Optional[str] = None

        # Default to verified TLS (certifi, like curl). On prod behind a MITM
        # egress proxy, verification fails → fall back to verify=False (urllib3
        # still sends SNI, so routing stays correct). Force with env if needed.
        verify = os.getenv("MODEL_ARMOR_INSECURE_SSL", "").lower() not in ("1", "true", "yes")

        def _post(verify_flag: bool):
            if not verify_flag:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            return requests.post(
                self._endpoint, json=payload, headers=headers,
                timeout=self._BASE_TIMEOUT, verify=verify_flag,
            )

        for attempt in range(1, self._MAX_RETRIES + 1):
            try:
                try:
                    resp = await asyncio.to_thread(_post, verify)
                except requests.exceptions.SSLError:
                    # MITM proxy — drop verification (SNI preserved) and retry.
                    if verify:
                        verify = False
                        self.console.print(
                            "[yellow]⚠ Model Armor TLS verification failed (proxy MITM) — "
                            "retrying without verification.[/]"
                        )
                        resp = await asyncio.to_thread(_post, verify)
                    else:
                        raise

                if resp.status_code == 200:
                    return self._extract_response(resp.text)
                elif resp.status_code in self._RETRY_STATUSES and attempt < self._MAX_RETRIES:
                    last_error = f"HTTP {resp.status_code}"
                    await asyncio.sleep(self._RETRY_BACKOFF_BASE ** (attempt - 1))
                    continue
                else:
                    return f"ERROR: Model Armor API error {resp.status_code}: {resp.text[:500]}"

            except requests.exceptions.Timeout:
                last_error = f"Request timed out after {self._BASE_TIMEOUT}s"
                if attempt < self._MAX_RETRIES:
                    await asyncio.sleep(self._RETRY_BACKOFF_BASE ** (attempt - 1))
                    continue
            except requests.exceptions.RequestException as e:
                last_error = f"{type(e).__name__}: {e}"
                if attempt < self._MAX_RETRIES:
                    await asyncio.sleep(self._RETRY_BACKOFF_BASE ** (attempt - 1))
                    continue
            except Exception as e:
                return f"ERROR: Model Armor request failed ({type(e).__name__}): {e}"

        return f"ERROR: Model Armor request failed after {self._MAX_RETRIES} attempts: {last_error}"

    def _extract_response(self, response_text: str) -> str:
        """Parse sanitizeUserPrompt response.

        Blocked:  sanitizationResult.filterMatchState == "MATCH_FOUND"
        Accepted: sanitizationResult.filterMatchState == "NO_MATCH_FOUND"
        """
        try:
            data = json.loads(response_text)
        except json.JSONDecodeError:
            return response_text.strip() or "ERROR: Empty response from Model Armor"

        result = data.get("sanitizationResult", {})
        match_state = result.get("filterMatchState", "")

        if match_state == "MATCH_FOUND":
            # Collect which filters triggered
            triggered = []
            for fname, fdata in (result.get("filterResults") or {}).items():
                if isinstance(fdata, dict) and fdata.get("filterMatchState") == "MATCH_FOUND":
                    rai = fdata.get("raiFilterResult", {})
                    categories = rai.get("matchedRaiCategories") or []
                    label = ", ".join(categories) if categories else fname.upper()
                    triggered.append(label)
            reason = "; ".join(triggered) if triggered else "Policy violation detected"
            return f"BLOCKED: {reason} (Model Armor)"

        if match_state == "NO_MATCH_FOUND":
            return "PASS: Accepted by Model Armor"

        # Fallback — unexpected shape
        return f"PASS: {response_text[:200]}"


class LLMGuardHandler(BaseModelHandler):
    """Handler for LLM Guard guardrail service with full LLM integration."""
    
    def __init__(self, model_config: Dict[str, Any], custom_config: Dict[str, Any]):
        super().__init__(model_config)
        self.base_url = custom_config.get("base_url", os.getenv("LLM_GUARD_BASE_URL", ""))
        self.llm_endpoint = custom_config.get("llm_endpoint", os.getenv("LLM_GUARD_ENDPOINT", ""))
        self.model_name = custom_config.get("model_name", "")
        self.min_consensus = custom_config.get("min_consensus", 2)
        self.output_min_consensus = custom_config.get("output_min_consensus", 2)
        self.max_tokens = custom_config.get("max_tokens", 120)
        self.temperature = custom_config.get("temperature", 0)
        
        # Default guardrail configuration
        self.guardrail_conf = custom_config.get("guardrail_conf", [
            {
                "name": "list_checker",
                "required": True,
                "mandatory_accept": False,
                "parameters": "{\"fuzzy\": \"true\"}",
                "is_llm": False
            },
            {
                "name": "llm_guard",
                "required": True,
                "mandatory_accept": False,
                "parameters": "{}",
                "is_llm": True
            }
        ])
    
    async def generate_response(self, prompt: str) -> str:
        """Generate response through LLM Guard guardrail evaluation with full LLM"""
        try:
            payload = {
                "aegis_payload": {
                    "input": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "guardrail_conf": self.guardrail_conf,
                    "min_consensus": self.min_consensus,
                    "output_min_consensus": self.output_min_consensus
                },
                "llm_payload": {
                    "model": self.model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a helpful assistant."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature,
                    "top_p": 1,
                    "stop": ["<|eot_id|>"]
                },
                "llm_endpoint": self.llm_endpoint
            }
            
            headers = {
                "Content-Type": "application/json"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/v1/evaluate_prompt",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=90)  # LLM Guard can be slower due to full LLM
                ) as response:
                    response_text = await response.text()
                    
                    # LLM Guard returns accepted:true/false in the response body
                    # Both 200 and 400 can contain valid responses to parse
                    if response.status in [200, 400]:
                        return self._extract_response(response_text)
                    else:
                        return f"ERROR: LLM Guard API error {response.status}: {response_text}"
        
        except Exception as e:
            return f"ERROR: LLM Guard request failed: {str(e)}"
    
    def _extract_blocked_response(self, response_text: str) -> str:
        """Extract blocking reason from LLM Guard guardrail rejection"""
        try:
            data = json.loads(response_text)
            
            if isinstance(data, dict):
                # Check for accepted flag
                if data.get("accepted") == False:
                    # Extract guardrail responses
                    aegis_responses = data.get("aegis_response", [])
                    reasons = []
                    for guard in aegis_responses:
                        if guard.get("accepted") == False:
                            name = guard.get("name", "unknown")
                            reason = guard.get("reason", "blocked")
                            reasons.append(f"{name}: {reason}")
                    
                    if reasons:
                        return f"BLOCKED: {'; '.join(reasons)}"
                    return "BLOCKED: Request rejected by LLM Guard"
                
                if "error" in data:
                    return f"BLOCKED: {data['error']}"
                if "message" in data:
                    return f"BLOCKED: {data['message']}"
            
            return f"BLOCKED: {response_text}"
            
        except json.JSONDecodeError:
            return f"BLOCKED: {response_text}"
    
    def _extract_response(self, response_text: str) -> str:
        """Extract the actual response from LLM Guard output.
        
        LLM Guard response format:
        - accepted: true/false (main decision)
        - aegis_response: array of guardrail results with name, accepted, reason
        - llm_response: LLM output (if accepted=true)
        - output_moderated: whether output was moderated
        """
        try:
            data = json.loads(response_text)
            
            if isinstance(data, dict):
                # PRIMARY CHECK: Use "accepted" field to determine bypass vs blocked
                accepted = data.get("accepted")
                
                if accepted == False:
                    aegis_responses = data.get("aegis_response", [])
                    reasons = []
                    for guard in aegis_responses:
                        if guard.get("accepted") == False:
                            name = guard.get("name", "unknown")
                            reason = guard.get("reason", "blocked")
                            reasons.append(f"{name}: {reason}")
                    
                    if reasons:
                        return f"BLOCKED: {'; '.join(reasons)}"
                    return "BLOCKED: Request rejected by LLM Guard guardrails"
                
                elif accepted == True:
                    # BYPASSED - Guardrails passed, extract LLM response
                    if "llm_response" in data:
                        llm_resp = data["llm_response"]
                        if isinstance(llm_resp, dict):
                            # Extract content from choices (OpenAI format)
                            choices = llm_resp.get("choices", [])
                            if choices and isinstance(choices, list):
                                first_choice = choices[0]
                                if isinstance(first_choice, dict):
                                    message = first_choice.get("message", {})
                                    if isinstance(message, dict):
                                        content = message.get("content")
                                        if content:
                                            return content
                            # Try direct content fields
                            if llm_resp.get("content"):
                                return llm_resp["content"]
                            if llm_resp.get("response"):
                                return llm_resp["response"]
                        return str(llm_resp)
                    
                    # If no LLM response but accepted=true, return pass message
                    return "PASS: Request approved by LLM Guard (no LLM response)"
                
                # Fallback: Check other status indicators
                if data.get("blocked") or data.get("rejected"):
                    reason = data.get("reason", data.get("message", "Blocked"))
                    return f"BLOCKED: {reason}"
                
                if data.get("status") == "PASS":
                    return "PASS: Request approved"
                
                # Try to extract any response content
                if "llm_response" in data:
                    return str(data["llm_response"])
                if "response" in data:
                    return data["response"]
                if "content" in data:
                    return data["content"]
                if "msg" in data:
                    return str(data["msg"])
            
            return str(data)
            
        except json.JSONDecodeError:
            return response_text if response_text else "ERROR: Empty response from LLM Guard"


class ConvAIHandler(BaseModelHandler):
    """Handler for ConvAI (Conversational AI) bot models."""
    
    def __init__(self, model_config: Dict[str, Any], custom_config: Dict[str, Any]):
        super().__init__(model_config)
        self.base_url = custom_config.get("base_url", os.getenv("CONV_AI_BASE_URL", ""))
        self.tenant_id = custom_config.get("tenant_id", os.getenv("CONV_AI_TENANT_ID", ""))
        self.account_id = custom_config.get("account_id", "")
        self.agent_name = custom_config.get("agent_name", "")
        
        # Session state - will be initialized on first call
        self._conversation_id = None
        self._session_initialized = False
        self._random_suffix = None
    
    def _generate_conversation_id(self) -> str:
        """Generate a unique conversation ID"""
        import secrets
        self._random_suffix = secrets.token_hex(4)
        return f"{self.account_id}_{self._random_suffix}_EDN"
    
    def _base64_encode(self, data: dict) -> str:
        """Base64 encode a dictionary as JSON"""
        import base64
        json_str = json.dumps(data)
        return base64.b64encode(json_str.encode()).decode()
    
    def _base64_decode(self, encoded: str) -> dict:
        """Base64 decode a string to dictionary"""
        import base64
        try:
            decoded = base64.b64decode(encoded).decode()
            return json.loads(decoded)
        except Exception:
            return {}
    
    async def _initialize_session(self) -> bool:
        """Initialize ConvAI bot session"""
        self._conversation_id = self._generate_conversation_id()
        
        # Base64 encoded context
        context_data = {
            "context": "{\"features\":{\"pincode\":\"560103\",\"abIds\":\"\",\"lid\":\"LSTMOBGMXSWFYZYWKTDQAAZ6F\",\"pid\":\"MOBGMXSWFYZYWKTD\"}}",
            "chatType": "DA"
        }
        context_b64 = self._base64_encode(context_data)
        
        init_payload = {
            "message": {
                "data": {
                    "type": "CHAT_START",
                    "body": context_b64
                },
                "modality": "CHAT",
                "channel": "UNKNOWN",
                "sessionId": f"{self._conversation_id}#202405#0",
                "client_message_id": str(__import__('uuid').uuid4()),
                "topic_id": self._conversation_id,
                "sender_id": "ACC8F523BD4F8B947E48019C84B760DEAC1V",
                "content_type": "SIGNAL",
                "generated_by": "USER",
                "message_tags": [],
                "channel_id": "acf0257300ee82368fbc0176b67252c5",
                "conversation_id": self._conversation_id,
                "sender_type": "BUYER",
                "hybrid_timestamp": {
                    "physical_time": int(__import__('time').time() * 1000),
                    "logical_time": 1
                },
                "transcript_id": "1686736163217001b825f8",
                "created_at": ""
            },
            "mode": "START",
            "source": "BOT_PROXY",
            "conversation_id": self._conversation_id,
            "session_derived_data": {
                "conversation_id": self._conversation_id,
                "data_key": "session_id",
                "data_value": f"{self._conversation_id}#202424#0",
                "start_transcript_id": "1686736163217001b825f8",
                "scope_id": f"{self._conversation_id}#202324#0",
                "derived_id": f"{self._conversation_id}_376372_EDN#202324#0",
                "updated_by": "CM"
            },
            "invocation_context": "{\"features\":{\"pincode\":\"577201\",\"pageType\":\"productPage\"}}"
        }
        
        headers = {
            "X-TENANT-ID": self.tenant_id,
            "Content-Type": "application/json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/initialize-bot",
                    json=init_payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        # Check if initialization succeeded
                        if "entity" in data:
                            self._session_initialized = True
                            self.console.print(f"[green]✓ ConvAI session initialized: {self._conversation_id}[/]")
                            return True
                        else:
                            self.console.print(f"[red]✗ ConvAI init response missing 'entity'[/]")
                            return False
                    else:
                        error_text = await response.text()
                        self.console.print(f"[red]✗ ConvAI init failed: {response.status} - {error_text}[/]")
                        return False
        except Exception as e:
            self.console.print(f"[red]✗ ConvAI init error: {e}[/]")
            return False
    
    def _extract_bot_response(self, response_text: str) -> str:
        """Extract bot's text response from streaming ConvAI response"""
        messages = []
        
        # ConvAI returns multiple JSON objects, one per line
        for line in response_text.strip().split('\n'):
            if not line.strip():
                continue
            try:
                frame = json.loads(line)
                frame_data = frame.get("frameData", {})
                body = frame_data.get("body")
                
                if body:
                    decoded = self._base64_decode(body)
                    
                    # Try various paths to extract text
                    text = None
                    
                    # Path 1: stream view with widget
                    if "data" in decoded and "widget" in decoded["data"]:
                        widget = decoded["data"]["widget"]
                        if "data" in widget and "textMessage" in widget["data"]:
                            text = widget["data"]["textMessage"].get("value", {}).get("text")
                    
                    # Path 2: direct textMessage
                    if not text and "data" in decoded and "textMessage" in decoded["data"]:
                        text = decoded["data"]["textMessage"].get("value", {}).get("text")
                    
                    # Path 3: altText fallback
                    if not text:
                        alt_text = decoded.get("altText", "")
                        if alt_text and not alt_text.endswith("__"):
                            text = alt_text.rstrip("_")
                    
                    if text and text.strip():
                        messages.append(text)
                        
            except json.JSONDecodeError:
                continue
        
        # Return the longest message (usually the actual response)
        if messages:
            return max(messages, key=len)
        return ""
    
    async def generate_response(self, prompt: str) -> str:
        """Generate response from ConvAI bot"""
        try:
            # Initialize session if not already done
            if not self._session_initialized:
                success = await self._initialize_session()
                if not success:
                    return "ERROR: Failed to initialize ConvAI session"
            
            # Build message frame
            frame_data = {
                "type": "text",
                "data": {
                    "feedback": None,
                    "altText": None,
                    "textMessage": {
                        "value": {
                            "type": "TEXT_MESSAGE_VALUE",
                            "text": prompt,
                            "translatedText": prompt
                        }
                    }
                },
                "altText": f"{prompt}__"
            }
            
            message_payload = {
                "incoming_frame": {
                    "chatId": self._conversation_id,
                    "frameId": str(__import__('uuid').uuid4()),
                    "frameVersion": 3,
                    "transcriptId": "1642518351008001c5be60",
                    "frameType": "CHAT_MESSAGE",
                    "frameData": {
                        "body": self._base64_encode(frame_data),
                        "jsonBody": None,
                        "messageId": None,
                        "widgetType": "text"
                    },
                    "hybridTimestamp": {
                        "physicalTime": int(__import__('time').time() * 1000),
                        "logicalTime": 0
                    },
                    "senderDomain": "BUYER",
                    "historicalFrame": False,
                    "perfFrame": False,
                    "tenant": self.tenant_id,
                    "handler": "EDN_BOT",
                    "channel": "ANDROID",
                    "requestingVisitorId": "test",
                    "sessionId": f"{self._conversation_id}#12355"
                },
                "conversation_id": self._conversation_id,
                "streaming_id": None
            }
            
            headers = {
                "X-TENANT-ID": self.tenant_id,
                "Content-Type": "application/json"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/message/process",
                    json=message_payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=60)  # ConvAI can be slower
                ) as response:
                    if response.status == 200:
                        response_text = await response.text()
                        bot_response = self._extract_bot_response(response_text)
                        
                        if bot_response:
                            return bot_response
                        else:
                            return "ERROR: Could not extract response from ConvAI bot"
                    else:
                        error_text = await response.text()
                        return f"ERROR: ConvAI message failed: {response.status} - {error_text}"
        
        except Exception as e:
            return f"ERROR: ConvAI request failed: {str(e)}"
    
    async def reset_session(self):
        """Reset the ConvAI session (for starting a new conversation)"""
        self._conversation_id = None
        self._session_initialized = False
        self._random_suffix = None


class ModelHandlerFactory:
    """Factory for creating model handlers"""
    
    @staticmethod
    async def create_handler(model_config: Dict[str, Any]) -> Optional[BaseModelHandler]:
        """Create appropriate model handler based on provider"""
        provider = model_config.get("provider", "").lower()
        
        try:
            if provider == "openai":
                return OpenAIHandler(model_config)
            elif provider == "anthropic":
                return AnthropicHandler(model_config)
            elif provider == "gemini":
                return GeminiHandler(model_config)
            elif provider == "self-hosted":
                return SelfHostedHandler(model_config)
            elif provider == "custom-api":
                # STRICT MODE: custom_config with curl_command is REQUIRED
                custom_config = model_config.get("custom_config")
                if not custom_config:
                    raise ValueError(f"custom-api provider requires 'custom_config' with curl_command. Model: {model_config.get('model_id', 'unknown')}")
                
                if custom_config.get("type") == "proxy":
                    return ProxyTargetHandler(model_config, custom_config)
                elif custom_config.get("curl_command"):
                    return CustomCurlHandler(model_config, custom_config)
                else:
                    raise ValueError(f"custom-api requires either type='proxy' or 'curl_command'. Model: {model_config.get('model_id', 'unknown')}")
            elif provider == "custom":
                # Legacy support - requires custom_config with curl
                custom_config = model_config.get("custom_config")
                if not custom_config or not custom_config.get("curl_command"):
                    raise ValueError(f"'custom' provider requires custom_config with curl_command. Model: {model_config.get('model_id', 'unknown')}")
                return CustomCurlHandler(model_config, custom_config)
            elif provider == "huggingface":
                return HuggingFaceHandler(model_config)
            elif provider == "slap":
                # ConvAI bot handler
                custom_config = model_config.get("custom_config", {})
                return ConvAIHandler(model_config, custom_config)
            elif provider in ("guardrail-v1", "aegis"):
                custom_config = model_config.get("custom_config", {})
                return GuardrailHandler(model_config, custom_config)
            elif provider in ("guardrail-v2", "aegis-v2"):
                # Guardrail v2 handler
                custom_config = model_config.get("custom_config", {})
                return GuardrailV2Handler(model_config, custom_config)
            elif provider == "llm-guard":
                # LLM Guard guardrail service
                custom_config = model_config.get("custom_config", {})
                return LLMGuardHandler(model_config, custom_config)
            elif provider == "model-armor":
                # Google Cloud Model Armor guardrail
                custom_config = model_config.get("custom_config", {})
                return ModelArmorHandler(model_config, custom_config)
            else:
                raise ValueError(f"Unsupported provider: {provider}")
        
        except Exception as e:
            console = Console()
            console.print(f"[red]Error creating handler for {provider}: {str(e)}[/]")
            console.print(f"[red]Model config: {model_config}[/]")
            return None