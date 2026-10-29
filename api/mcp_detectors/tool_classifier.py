"""
Tool Classification Module — Triksha edition

Classifies MCP tools into security risk categories using the user-configured
LLM provider (OpenAI / Anthropic / Gemini), with the API key entered in
Settings. Routes through llm_providers — no internal gateway involved.
"""

import json
import os
import asyncio
from typing import List, Dict, Any, Optional
from rich.console import Console
import llm_providers

console = Console()


class ToolClassifier:
    """Classifies MCP tools into security risk categories using the configured LLM provider."""
    
    def __init__(self, api_key: Optional[str] = None, verbose: bool = False):
        """Initialize the tool classifier
        
        Args:
            api_key: Unused in OSS; the provider key comes from Settings/env. Kept
                for backward compatibility with existing callers.
            verbose: Whether to show detailed progress messages
        """
        self.verbose = verbose
        
        if not llm_providers.is_configured():
            console.print("[red]✗ No LLM provider API key configured for tool classification (set it in Settings)[/]")
    
    async def _call_gemini_api(self, prompt: str, max_tokens: int = 1000, temperature: float = 0.2) -> str:
        """Run a completion against the user-configured LLM provider.
        
        Args:
            prompt: The prompt to send
            max_tokens: Maximum output tokens
            temperature: Temperature for generation
            
        Returns:
            Response text from the provider
        """
        # Run blocking provider call in a thread to avoid blocking the event loop
        response_text = await asyncio.to_thread(
            llm_providers.complete_sync,
            prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        if not response_text:
            raise Exception("No response text from LLM provider")

        return response_text.strip()
    
    def _extract_json_from_response(self, response_text: str) -> Dict[str, Any]:
        """Extract JSON from response text, handling markdown code blocks
        
        Args:
            response_text: Raw response text
            
        Returns:
            Parsed JSON dictionary
        """
        # Remove markdown code blocks if present
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        # Find JSON object in response
        start_idx = response_text.find('{')
        end_idx = response_text.rfind('}') + 1
        
        if start_idx != -1 and end_idx != -1:
            json_str = response_text[start_idx:end_idx]
            return json.loads(json_str)
        else:
            # Try to find JSON array
            start_idx = response_text.find('[')
            end_idx = response_text.rfind(']') + 1
            if start_idx != -1 and end_idx != -1:
                json_str = response_text[start_idx:end_idx]
                return json.loads(json_str)
        
        raise ValueError("No JSON found in response")
    
    def _build_classification_prompt(
        self,
        tool_name: str,
        tool_description: str,
        tool_params: Dict[str, Any]
    ) -> str:
        """Build the classification prompt for a tool
        
        Args:
            tool_name: Name of the tool
            tool_description: Description of the tool
            tool_params: Tool parameters/input schema
            
        Returns:
            Formatted classification prompt
        """
        classification_prompt = f"""
You are a security classification expert.
Analyze this MCP tool and classify its risk category.

Tool Name: {tool_name}
Description: {tool_description}
Parameters: {json.dumps(tool_params, indent=2)}

Choose one or more categories:
- File Access / Exfiltration
- Database / Query Execution
- Command Execution / Shell Access
- Network / External API Calls
- Prompt Injection / Data Leakage
- Safe (Read-Only / Harmless)

Respond as JSON with:
{{
  "category": "...",
  "risk_level": "...",
  "reasoning": "..."
}}
"""
        return classification_prompt.strip()
    
    def _build_agentic_prompt(
        self,
        tool_name: str,
        tool_description: str,
        tool_params: Dict[str, Any],
        classification_data: Dict[str, Any]
    ) -> str:
        """Build the agentic reasoning prompt
        
        Args:
            tool_name: Name of the tool
            tool_description: Description of the tool
            tool_params: Tool parameters/input schema
            classification_data: Classification result from step 1
            
        Returns:
            Formatted agentic reasoning prompt
        """
        agentic_prompt = f"""
You are a team of 3 security AI agents analyzing this MCP tool.

[1] Classifier Agent:
    Determine the tool's purpose and potential misuse vectors.
[2] Red-Team Agent:
    Imagine how an attacker might abuse its inputs to exfiltrate data or execute code.
[3] Blue-Team Agent:
    Suggest safe call boundaries and mitigations.

Tool Context:
Name: {tool_name}
Description: {tool_description}
Parameters: {json.dumps(tool_params, indent=2)}
Classification: {json.dumps(classification_data, indent=2)}

Produce a concise collaborative analysis in JSON:
{{
  "summary": "...",
  "risks_identified": ["..."],
  "recommended_fuzz_types": ["SQLi", "PathTraversal", ...],
  "security_mitigation_advice": "..."
}}
"""
        return agentic_prompt.strip()
    
    def _build_fuzz_prompt(
        self,
        tool_name: str,
        tool_description: str,
        tool_params: Dict[str, Any],
        classification_data: Dict[str, Any]
    ) -> str:
        """Build the payload generation prompt
        
        Args:
            tool_name: Name of the tool
            tool_description: Description of the tool
            tool_params: Tool parameters/input schema
            classification_data: Classification result from step 1
            
        Returns:
            Formatted payload generation prompt
        """
        fuzz_prompt = f"""
You are a red-team payload generator AI.
Based on this tool's description and context, create 5 realistic adversarial payloads
to test its security.

Tool: {tool_name}
Description: {tool_description}
Parameters: {json.dumps(tool_params, indent=2)}
Context Classification: {json.dumps(classification_data, indent=2)}

Include payloads relevant to the context. For example:
- SQL tools → SQLi fuzz
- File tools → path traversal
- Shell tools → command injection
- API tools → SSRF, prompt injection

Return JSON list of 5 entries:
[
  {{
    "param": "<parameter_name>",
    "payload": "<attack_string>",
    "attack_type": "<type>",
    "intent": "<what it's testing>"
  }}
]
"""
        return fuzz_prompt.strip()
    
    async def classify_tool(
        self,
        tool: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Classify a single tool and perform comprehensive security analysis
        Includes: Classification, Agentic Reasoning, and Payload Generation
        
        Args:
            tool: Tool dictionary with 'name', 'description', and 'input_schema'
            
        Returns:
            Comprehensive analysis result with classification, agentic analysis, and payloads
        """
        tool_name = tool.get("name", "unnamed")
        tool_description = tool.get("description", "")
        tool_params = tool.get("input_schema", {})
        
        result = {
            "tool_name": tool_name,
            "tool_description": tool_description,
            "tool_params": tool_params,
            "classification": {},
            "agentic_analysis": {},
            "payloads": []
        }
        
        if self.verbose:
            console.print(f"[cyan]Analyzing tool: {tool_name}[/]")
        
        # STEP 1 — CLASSIFICATION
        try:
            if self.verbose:
                console.print(f"[dim]Step 1: Classifying tool...[/]")
            
            classification_prompt = self._build_classification_prompt(
                tool_name,
                tool_description,
                tool_params
            )
            
            classification_response = await self._call_gemini_api(
                classification_prompt,
                max_tokens=1000,
                temperature=0.2
            )
            
            try:
                classification_data = self._extract_json_from_response(classification_response)
                classification_data["tool_name"] = tool_name
                result["classification"] = classification_data
                
                if self.verbose:
                    console.print(f"[green]✓ Classified: {classification_data.get('category', 'Unknown')} ({classification_data.get('risk_level', 'Unknown')})[/]")
            except (ValueError, json.JSONDecodeError) as e:
                if self.verbose:
                    console.print(f"[yellow]Failed to parse classification JSON: {str(e)}[/]")
                result["classification"] = {
                    "category": "Unknown",
                    "risk_level": "Unknown",
                    "reasoning": classification_response,
                    "raw_response": classification_response
                }
        
        except Exception as e:
            error_msg = f"Classification failed: {str(e)}"
            if self.verbose:
                console.print(f"[red]✗ {error_msg}[/]")
            result["classification"] = {
                "category": "Unknown",
                "risk_level": "Unknown",
                "reasoning": error_msg,
                "error": error_msg
            }
        
        # STEP 2 — AGENTIC REASONING
        try:
            if self.verbose:
                console.print(f"[dim]Step 2: Running agentic reasoning (3-agent analysis)...[/]")
            
            agentic_prompt = self._build_agentic_prompt(
                tool_name,
                tool_description,
                tool_params,
                result["classification"]
            )
            
            agentic_response = await self._call_gemini_api(
                agentic_prompt,
                max_tokens=1500,
                temperature=0.3
            )
            
            try:
                agentic_data = self._extract_json_from_response(agentic_response)
                result["agentic_analysis"] = agentic_data
                
                if self.verbose:
                    risks_count = len(agentic_data.get("risks_identified", []))
                    console.print(f"[green]✓ Agentic analysis complete: {risks_count} risk(s) identified[/]")
            except (ValueError, json.JSONDecodeError) as e:
                if self.verbose:
                    console.print(f"[yellow]Failed to parse agentic analysis JSON: {str(e)}[/]")
                result["agentic_analysis"] = {
                    "summary": agentic_response,
                    "raw_response": agentic_response
                }
        
        except Exception as e:
            error_msg = f"Agentic reasoning failed: {str(e)}"
            if self.verbose:
                console.print(f"[red]✗ {error_msg}[/]")
            result["agentic_analysis"] = {
                "summary": error_msg,
                "error": error_msg
            }
        
        # STEP 3 — PAYLOAD GENERATION
        try:
            if self.verbose:
                console.print(f"[dim]Step 3: Generating fuzzing payloads...[/]")
            
            fuzz_prompt = self._build_fuzz_prompt(
                tool_name,
                tool_description,
                tool_params,
                result["classification"]
            )
            
            fuzz_response = await self._call_gemini_api(
                fuzz_prompt,
                max_tokens=2000,
                temperature=0.4
            )
            
            try:
                payloads_data = self._extract_json_from_response(fuzz_response)
                # Ensure it's a list
                if isinstance(payloads_data, list):
                    result["payloads"] = payloads_data
                elif isinstance(payloads_data, dict) and "payloads" in payloads_data:
                    result["payloads"] = payloads_data["payloads"]
                else:
                    result["payloads"] = [payloads_data] if payloads_data else []
                
                if self.verbose:
                    console.print(f"[green]✓ Generated {len(result['payloads'])} payload(s)[/]")
            except (ValueError, json.JSONDecodeError) as e:
                if self.verbose:
                    console.print(f"[yellow]Failed to parse payloads JSON: {str(e)}[/]")
                result["payloads"] = []
                result["payloads_raw"] = fuzz_response
        
        except Exception as e:
            error_msg = f"Payload generation failed: {str(e)}"
            if self.verbose:
                console.print(f"[red]✗ {error_msg}[/]")
            result["payloads"] = []
            result["payloads_error"] = error_msg
        
        if self.verbose:
            console.print(f"[green]✓ Complete analysis for {tool_name}[/]")
        
        return result
    
    async def classify_tools(
        self,
        tools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze multiple tools using Gemini 2.5 Flash
        Performs classification, agentic reasoning, and payload generation for each tool
        
        Args:
            tools: List of tool dictionaries from result.tools
            
        Returns:
            List of comprehensive analysis results for each tool
        """
        if not tools:
            if self.verbose:
                console.print("[yellow]No tools to analyze[/]")
            return []
        
        if self.verbose:
            console.print(f"[cyan]Analyzing {len(tools)} tool(s) using Gemini 2.5 Flash...[/]")
        
        # Analyze all tools (can be done concurrently, but sequential for better rate limiting)
        # For now, sequential to avoid rate limits; can be made concurrent if needed
        results = []
        for i, tool in enumerate(tools):
            if self.verbose:
                console.print(f"[cyan]Processing tool {i+1}/{len(tools)}[/]")
            try:
                result = await self.classify_tool(tool)
                results.append(result)
            except Exception as e:
                tool_name = tool.get("name", "unnamed")
                if self.verbose:
                    console.print(f"[red]✗ Error analyzing {tool_name}: {str(e)}[/]")
                results.append({
                    "tool_name": tool_name,
                    "error": str(e),
                    "classification": {},
                    "agentic_analysis": {},
                    "payloads": []
                })
        
        if self.verbose:
            console.print(f"[green]✓ Completed analysis of {len(results)} tool(s)[/]")
        
        return results


async def classify_mcp_tools(
    tools: List[Dict[str, Any]],
    api_key: Optional[str] = None,
    verbose: bool = False
) -> List[Dict[str, Any]]:
    """Convenience function to analyze MCP tools with comprehensive security analysis
    Performs: Classification, Agentic Reasoning, and Payload Generation
    
    Args:
        tools: List of tool dictionaries from result.tools (mcp_scanner.py)
        api_key: Optional LLM API key
        verbose: Whether to show detailed progress
        
    Returns:
        List of comprehensive analysis results with:
        - classification: category, risk_level, reasoning
        - agentic_analysis: summary, risks_identified, recommended_fuzz_types, security_mitigation_advice
        - payloads: list of 5 fuzzing payloads with param, payload, attack_type, intent
        
    Example:
        >>> from mcp_detectors.tool_classifier import classify_mcp_tools
        >>> tools = result.tools  # From mcp_scanner.py
        >>> analyses = await classify_mcp_tools(tools, verbose=True)
        >>> for analysis in analyses:
        ...     print(f"Tool: {analysis['tool_name']}")
        ...     print(f"Category: {analysis['classification']['category']}")
        ...     print(f"Risk Level: {analysis['classification']['risk_level']}")
        ...     print(f"Payloads: {len(analysis['payloads'])}")
        ...     # Use payloads to invoke tools from MCP server
    """
    classifier = ToolClassifier(api_key=api_key, verbose=verbose)
    return await classifier.classify_tools(tools)

