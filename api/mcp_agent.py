"""
MCP Security Agent - Autonomous security testing for MCP tools

This agent autonomously performs security testing on MCP tools using an LLM-powered
agentic approach. It iteratively generates test cases, executes them, and analyzes results.
"""

import json
import asyncio
from typing import Dict, Any, List, Optional, AsyncGenerator
from datetime import datetime
from rich.console import Console
from llm_client import APILLMClient
from mcp_scanner import MCPScanner


class MCPSecurityAgent:
    """Autonomous agent for MCP tool security testing"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.llm_client = APILLMClient(console=self.console)
        self.scanner = MCPScanner(console=self.console, enable_llm_analysis=False)
        from mcp_attack_knowledge import MCPAttackKnowledgeBase
        self.knowledge_base = MCPAttackKnowledgeBase()
    
    async def run_autonomous_test(
        self,
        server_url: str,
        server_type: str,
        tool_name: str,
        tool_description: str,
        tool_input_schema: Dict[str, Any],
        security_tests: List[Dict[str, Any]],
        server_context: Dict[str, Any],  # Full server scan data with all findings
        headers: Optional[Dict[str, str]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Run autonomous security testing on a specific MCP tool
        
        Args:
            server_url: MCP server URL
            server_type: Server type (http/sse)
            tool_name: Name of the tool to test
            tool_description: Tool description
            tool_input_schema: Tool's input schema
            security_tests: List of security test cases from the scan
            headers: Optional HTTP headers
            
        Yields:
            Progress updates as dict with 'type' and 'data' fields
        """
        yield {
            "type": "init",
            "data": {
                "message": f"🤖 Initializing autonomous security agent",
                "details": f"Target: {tool_name} | Server: {server_url}",
                "timestamp": datetime.now().isoformat()
            }
        }
        
        yield {
            "type": "log",
            "data": {
                "message": f"📋 Tool Input Schema Analysis",
                "details": f"Parameters: {len(tool_input_schema.get('properties', {}))} | Required: {len(tool_input_schema.get('required', []))}",
                "timestamp": datetime.now().isoformat()
            }
        }
        
        # Phase 1: Contextual analysis using scan findings
        yield {"type": "phase", "data": {"phase": 1, "name": "🔍 Contextual Threat Analysis"}}
        
        # Get relevant attack vectors from knowledge base
        parameters = list(tool_input_schema.get('properties', {}).keys())
        relevant_attacks = self.knowledge_base.get_relevant_attacks(
            tool_name, tool_description, parameters
        )
        
        yield {
            "type": "log",
            "data": {
                "message": f"📚 Loaded {len(relevant_attacks)} attack vectors from knowledge base",
                "details": f"Categories: {', '.join(set(a.category for a in relevant_attacks))}",
                "technical": True
            }
        }
        
        # Use LLM to analyze THIS specific tool with knowledge base context
        capability_analysis = await self._analyze_capabilities_contextual(
            tool_name, tool_description, tool_input_schema, server_context, relevant_attacks
        )
        
        yield {
            "type": "analysis",
            "data": {
                "message": f"🧠 LLM identified {len(capability_analysis.get('risks', []))} contextual risks",
                "details": f"Based on: {capability_analysis.get('reasoning', 'scan findings + tool behavior')}",
                "risks": capability_analysis.get('risks', [])
            }
        }
        
        # Phase 2: Generate contextual payloads using LLM + knowledge base
        yield {"type": "phase", "data": {"phase": 2, "name": "🎯 Contextual Payload Generation"}}
        
        test_scenarios = await self._generate_contextual_scenarios(
            tool_name, tool_description, tool_input_schema, 
            capability_analysis, server_context, relevant_attacks
        )
        
        yield {
            "type": "scenarios",
            "data": {
                "message": f"🧪 Generated {len(test_scenarios)} weaponized test vectors",
                "details": f"Attack types: {', '.join(set(s.get('attack_type', 'unknown') for s in test_scenarios))}",
                "count": len(test_scenarios)
            }
        }
        
        # Phase 3: Execute test scenarios
        yield {"type": "phase", "data": {"phase": 3, "name": "Executing Security Tests"}}
        
        results = []
        server_config = {
            "type": server_type,
            "url": server_url,
            "headers": headers or {}
        }
        
        for idx, scenario in enumerate(test_scenarios, 1):
            # Show test initiation with payload details
            args_preview = json.dumps(scenario.get('arguments', {}), indent=None)
            if len(args_preview) > 100:
                args_preview = args_preview[:100] + "..."
            
            yield {
                "type": "test_start",
                "data": {
                    "message": f"🔬 [{idx}/{len(test_scenarios)}] {scenario.get('name', 'Unknown')}",
                    "details": f"Attack: {scenario.get('attack_type', 'unknown')} | Target: {scenario.get('description', 'N/A')}",
                    "payload": args_preview
                }
            }
            
            # Show payload being sent
            yield {
                "type": "log",
                "data": {
                    "message": f"📤 Sending payload to {tool_name}",
                    "details": f"Arguments: {json.dumps(scenario.get('arguments', {}), indent=2)}",
                    "technical": True
                }
            }
            
            try:
                # Execute the tool with test inputs
                result = await self._execute_tool_test(
                    server_config, tool_name, scenario.get('arguments', {})
                )
                
                # Show raw response
                result_preview = json.dumps(result, indent=None)[:200]
                yield {
                    "type": "log",
                    "data": {
                        "message": f"📥 Response received from server",
                        "details": f"Status: {'ERROR' if result.get('isError') else 'SUCCESS'} | Size: {len(str(result))} bytes",
                        "technical": True
                    }
                }
                
                # Analyze the result
                yield {
                    "type": "log",
                    "data": {
                        "message": f"🔍 Analyzing response for security implications",
                        "details": "LLM-powered vulnerability detection in progress...",
                        "technical": True
                    }
                }
                
                analysis = await self._analyze_test_result(
                    scenario, result, tool_name
                )
                
                results.append({
                    "scenario": scenario,
                    "result": result,
                    "analysis": analysis
                })
                
                if analysis.get('is_vulnerable'):
                    yield {
                        "type": "vulnerability",
                        "data": {
                            "message": f"🚨 VULNERABILITY FOUND: {analysis.get('vulnerability_type', 'Unknown')}",
                            "severity": analysis.get('severity', 'medium').upper(),
                            "details": analysis.get('details', 'No details'),
                            "recommendation": analysis.get('recommendation', 'Review security controls'),
                            "payload": json.dumps(scenario.get('arguments', {}))
                        }
                    }
                else:
                    yield {
                        "type": "test_pass",
                        "data": {
                            "message": f"✅ Security control effective",
                            "details": f"No exploitable weakness detected with {scenario.get('attack_type')} attack"
                        }
                    }
                    
            except Exception as e:
                yield {
                    "type": "test_error",
                    "data": {
                        "message": f"❌ Execution failed: {str(e)[:100]}",
                        "details": f"Exception during {scenario.get('attack_type')} test",
                        "error": str(e)
                    }
                }
                results.append({
                    "scenario": scenario,
                    "error": str(e)
                })
            
            # Small delay between tests
            await asyncio.sleep(0.3)
        
        # Phase 4: Generate final report
        yield {"type": "phase", "data": {"phase": 4, "name": "Generating Security Report"}}
        
        final_report = await self._generate_final_report(
            tool_name, results, capability_analysis
        )
        
        yield {
            "type": "complete",
            "data": {
                "message": "🎉 Autonomous security testing complete",
                "report": final_report,
                "timestamp": datetime.now().isoformat()
            }
        }
    
    def _extract_json_from_llm_response(self, text: str) -> Any:
        """Robustly extract JSON from LLM response with various formats"""
        import re
        
        # Try multiple extraction methods
        methods = [
            # Method 1: ```json ... ```
            lambda t: re.search(r'```json\s*\n(.*?)\n```', t, re.DOTALL),
            # Method 2: ``` ... ```
            lambda t: re.search(r'```\s*\n(.*?)\n```', t, re.DOTALL),
            # Method 3: Look for JSON array/object directly
            lambda t: re.search(r'(\[[\s\S]*\]|\{[\s\S]*\})', t, re.DOTALL),
        ]
        
        for method in methods:
            match = method(text)
            if match:
                try:
                    json_str = match.group(1) if len(match.groups()) > 0 else match.group(0)
                    return json.loads(json_str.strip())
                except:
                    continue
        
        # If all fails, try parsing the whole text
        try:
            return json.loads(text.strip())
        except:
            raise ValueError("Could not extract JSON from LLM response")
    
    async def _analyze_capabilities_contextual(
        self, 
        tool_name: str, 
        description: str, 
        input_schema: Dict[str, Any],
        server_context: Dict[str, Any],
        relevant_attacks: List[Any]
    ) -> Dict[str, Any]:
        """Contextual capability analysis using scan findings + knowledge base"""
        
        # Extract scan findings about this specific tool
        tool_findings = server_context.get('security_findings', {}).get(tool_name, {}) if isinstance(server_context, dict) else {}
        pattern_findings = tool_findings.get('pattern_based', []) if isinstance(tool_findings, dict) else []
        capability_concerns = tool_findings.get('capability_concerns', []) if isinstance(tool_findings, dict) else []
        
        # Safely get parameters
        properties = input_schema.get('properties', {}) if isinstance(input_schema, dict) else {}
        param_list = list(properties.keys())
        required = input_schema.get('required', []) if isinstance(input_schema, dict) else []
        
        # Get attack knowledge
        attack_context = self.knowledge_base.get_attack_context_for_llm(
            tool_name, description, param_list
        )
        
        prompt = f"""You are an autonomous security agent analyzing an MCP tool with FULL CONTEXT.

=== TARGET TOOL ===
Name: {tool_name}
Description: {description}
Parameters: {json.dumps(properties, indent=2)}
Required: {required}

=== EXISTING SCAN FINDINGS ===
Pattern-based Detections: {json.dumps(pattern_findings, indent=2) if pattern_findings else "None"}
Capability Concerns: {json.dumps(capability_concerns, indent=2) if capability_concerns else "None"}

=== RELEVANT ATTACK KNOWLEDGE ===
{attack_context}

=== YOUR TASK ===
Based on the SPECIFIC characteristics of THIS tool:
1. What does "{tool_name}" actually DO based on its name and description?
2. Which parameters {param_list} are most dangerous and why?
3. What SPECIFIC attacks would work against THIS tool?
4. Given the existing findings, what ELSE should we test?

THINK CONTEXTUALLY:
- "read" tool → path traversal, file access, SSRF
- "query" or "search" → SQL/NoSQL injection
- "api" or "url" → SSRF
- "repo" or "github" → repo name injection, path traversal
- Consider parameter names and their usage

Return JSON with YOUR REASONING:
{{
  "reasoning": "Why THIS tool is vulnerable",
  "capabilities": ["what_this_tool_does"],
  "risks": [
    {{"type": "vulnerability_type", "description": "why", "severity": "critical|high|medium|low", "rationale": "Based on {param_list[0] if param_list else 'input'} usage"}}
  ],
  "attack_vectors": ["specific_attack_method"]
}}

Analyze now:"""
        
        try:
            response = await self.llm_client.generate_content(prompt)
            content = response.get("content", "")
            
            if isinstance(content, list) and len(content) > 0:
                text = content[0].get("text", "")
                self.console.print(f"[dim]LLM capability analysis: {len(text)} chars[/]")
                return self._extract_json_from_llm_response(text)
            
            raise ValueError("No content in LLM response")
            
        except Exception as e:
            self.console.print(f"[red]Capability analysis failed: {e}[/]")
            # Force the agent to think harder - retry with simpler prompt
            return await self._retry_capability_analysis(tool_name, description, input_schema)
    
    async def _retry_capability_analysis(
        self, tool_name: str, description: str, input_schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Retry with simpler, more directed prompt"""
        
        properties = input_schema.get('properties', {}) if isinstance(input_schema, dict) else {}
        params = list(properties.keys())
        
        prompt = f"""Analyze security risks for tool: {tool_name}

Description: {description}
Parameters: {', '.join(params) if params else 'unknown'}

What security vulnerabilities exist? Return JSON:
{{"capabilities": ["action1"], "risks": [{{"type": "vulnerability_type", "description": "why", "severity": "high"}}], "attack_vectors": ["how_to_attack"]}}"""
        
        try:
            response = await self.llm_client.generate_content(prompt)
            content = response.get("content", "")
            if isinstance(content, list) and len(content) > 0:
                text = content[0].get("text", "")
                return self._extract_json_from_llm_response(text)
        except Exception as e:
            # NO FALLBACK - LLM must succeed
            raise Exception(f"Capability analysis failed: {str(e)}. Agent cannot proceed without LLM reasoning.")
    
    async def _generate_contextual_scenarios(
        self,
        tool_name: str,
        description: str,
        input_schema: Dict[str, Any],
        capability_analysis: Dict[str, Any],
        server_context: Dict[str, Any],
        relevant_attacks: List[Any]
    ) -> List[Dict[str, Any]]:
        """Generate contextual test scenarios using LLM + scan context + knowledge base"""
        
        # Build contextual attack knowledge
        attack_techniques = {}
        for attack in relevant_attacks:
            attack_techniques[attack.id] = {
                "severity": attack.severity,
                "payloads": [p['value'] for p in attack.payloads[:5]],
                "techniques": [p['technique'] for p in attack.payloads[:5]]
            }
        
        # Extract tool-specific findings (with safety checks)
        tool_findings = server_context.get('security_findings', {}).get(tool_name, {}) if isinstance(server_context, dict) else {}
        server_capabilities = server_context.get('server_info', {}).get('capabilities', []) if isinstance(server_context, dict) else []
        
        properties = input_schema.get('properties', {}) if isinstance(input_schema, dict) else {}
        params = list(properties.keys())
        first_param = params[0] if params else "input"
        
        # Safety checks for capability_analysis
        reasoning = capability_analysis.get('reasoning', 'N/A') if isinstance(capability_analysis, dict) else 'N/A'
        risks = capability_analysis.get('risks', []) if isinstance(capability_analysis, dict) else []
        pattern_based = tool_findings.get('pattern_based', [])[:3] if isinstance(tool_findings, dict) else []
        
        prompt = f"""You are an autonomous security agent with FULL CONTEXT about this MCP server.

=== TOOL UNDER TEST ===
Tool: {tool_name}
Purpose: {description}
Parameters: {json.dumps(properties, indent=2)}

=== SCAN CONTEXT (What we already know) ===
LLM Reasoning: {reasoning}
Risks Found: {json.dumps(risks, indent=2)}
Existing Findings: {json.dumps(pattern_based, indent=2) if pattern_based else 'None'}

=== ATTACK KNOWLEDGE BASE ===
{json.dumps(attack_techniques, indent=2)}

=== CONTEXTUAL PAYLOAD GENERATION ===
Based on "{tool_name}", reason about what it ACTUALLY does:
- "read_wiki" → fetches GitHub docs, likely uses repoName in API call
- "redis_get" → database query, key parameter used in GET command
- "execute" → might run commands, check for shell injection

For THIS tool with param "{first_param}":
1. What is "{first_param}" used for in {tool_name}?
2. Which attacks from knowledge base fit THIS usage?
3. Adapt the payload to match expected input format
4. Create variations based on scan findings

Generate 10-12 CONTEXTUAL attacks adapted to "{tool_name}":

JSON array (NO markdown, NO examples, REAL payloads):
[
  {{
    "name": "Attack name specific to {tool_name}",
    "description": "Why this targets {tool_name}'s {first_param} parameter",
    "attack_type": "injection|access|exfiltration|abuse",
    "arguments": {{"{first_param}": "REAL_MALICIOUS_PAYLOAD"}},
    "expected_behavior": "What {tool_name} should do if secure"
  }}
]

Think contextually and generate:"""
        
        try:
            response = await self.llm_client.generate_content(prompt)
            content = response.get("content", "")
            
            if isinstance(content, list) and len(content) > 0:
                text = content[0].get("text", "")
                self.console.print(f"[dim]LLM generated {len(text)} chars of attack scenarios[/]")
                
                scenarios = self._extract_json_from_llm_response(text)
                
                if isinstance(scenarios, list) and len(scenarios) > 0:
                    self.console.print(f"[green]✓ LLM generated {len(scenarios)} custom attack scenarios[/]")
                    return scenarios
                
                raise ValueError("LLM returned empty or invalid scenario list")
            
            raise ValueError("No content in LLM response")
            
        except Exception as e:
            self.console.print(f"[yellow]⚠ LLM scenario generation attempt 1 failed: {str(e)[:100]}[/]")
            # Retry with more explicit prompt using knowledge base
            return await self._retry_with_knowledge_base(
                tool_name, input_schema, relevant_attacks, capability_analysis
            )
    
    async def _retry_with_knowledge_base(
        self,
        tool_name: str,
        input_schema: Dict[str, Any],
        relevant_attacks: List[Any],
        capability_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Retry using knowledge base to guide LLM with concrete examples"""
        
        params = list(input_schema.get('properties', {}).keys())
        first_param = params[0] if params else "input"
        
        # Get top payloads from knowledge base
        kb_payloads = []
        for attack in relevant_attacks[:6]:
            for p in attack.payloads[:3]:
                kb_payloads.append({
                    "attack_type": attack.name,
                    "payload": p['value'],
                    "technique": p['technique']
                })
        
        prompt = f"""You have a knowledge base of attack payloads. Adapt them for tool: {tool_name}

TARGET PARAMETER: {first_param}
TOOL PURPOSE (inferred): {tool_name.replace('_', ' ')}

KNOWLEDGE BASE PAYLOADS:
{json.dumps(kb_payloads[:10], indent=2)}

TASK: Adapt these payloads to test {tool_name}'s "{first_param}" parameter.
Consider what {tool_name} likely does with {first_param}.

Return 8-10 adapted tests as JSON array:
[{{"name":"attack_name", "attack_type":"type", "arguments":{{"{first_param}":"ADAPTED_PAYLOAD"}}, "description":"why", "expected_behavior":"should_block"}}]"""
        
        try:
            response = await self.llm_client.generate_content(prompt)
            content = response.get("content", "")
            if isinstance(content, list) and len(content) > 0:
                text = content[0].get("text", "")
                scenarios = self._extract_json_from_llm_response(text)
                if isinstance(scenarios, list) and len(scenarios) > 0:
                    self.console.print(f"[green]✓ KB-guided LLM: {len(scenarios)} scenarios[/]")
                    return scenarios
        except Exception as e:
            # NO FALLBACK - LLM must succeed
            raise Exception(f"Scenario generation failed: {str(e)}. Agent cannot proceed without LLM-generated payloads.")
    
    async def _execute_tool_test(
        self, server_config: Dict[str, Any], tool_name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a tool with test arguments"""
        
        timeout = 30
        async with self.scanner._get_client(server_config, timeout) as (read, write):
            from mcp import ClientSession
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
                
                # Convert MCP content objects to JSON-serializable format
                serialized_content = []
                for item in result.content:
                    if hasattr(item, 'model_dump'):
                        # Pydantic v2
                        serialized_content.append(item.model_dump())
                    elif hasattr(item, 'dict'):
                        # Pydantic v1
                        serialized_content.append(item.dict())
                    elif hasattr(item, '__dict__'):
                        # Fallback to dict
                        serialized_content.append(item.__dict__)
                    else:
                        # Convert to string if nothing works
                        serialized_content.append({"text": str(item)})
                
                return {
                    "content": serialized_content,
                    "isError": getattr(result, 'isError', False)
                }
    
    async def _analyze_test_result(
        self, scenario: Dict[str, Any], result: Dict[str, Any], tool_name: str
    ) -> Dict[str, Any]:
        """Analyze if test result indicates a vulnerability"""
        
        prompt = f"""You are a security analyst evaluating penetration test results.

ATTACK EXECUTED:
Name: {scenario.get('name')}
Type: {scenario.get('attack_type')}
Payload: {json.dumps(scenario.get('arguments', {}))}
Expected Secure Response: {scenario.get('expected_behavior')}

SERVER RESPONSE:
{json.dumps(result, indent=2)}

VULNERABILITY INDICATORS:
- **Error messages**: Stack traces, SQL errors, path disclosure → VULNERABLE
- **Unexpected data**: Data from other users/tables → VULNERABLE
- **No error with injection payload**: Payload not sanitized → VULNERABLE
- **Time delays**: Response delayed by payload → VULNERABLE
- **Internal IPs/metadata**: SSRF successful → VULNERABLE
- **Command output**: whoami, /etc/passwd → VULNERABLE

SECURE INDICATORS:
- **Generic error**: "Invalid input" without details → SECURE
- **Same response**: Payload treated as literal string → SECURE
- **Immediate rejection**: Input validation worked → SECURE

ANALYZE: Did the attack succeed? Look for:
1. Error messages revealing internal details
2. Successful data extraction
3. Command execution evidence
4. Timing differences (SQLi blind)
5. SSRF response data

Return JSON (no markdown):
{{
  "is_vulnerable": true,  // true if ANY indicator of successful attack
  "vulnerability_type": "sql_injection|command_injection|path_traversal|ssrf|etc",
  "severity": "critical",  // critical if RCE/data breach, high if data leak, medium if info disclosure
  "details": "Specific evidence from response showing vulnerability",
  "recommendation": "Specific fix: parameterized queries, input validation, etc"
}}

Analyze NOW:"""
        
        try:
            response = await self.llm_client.generate_content(prompt)
            content = response.get("content", "")
            
            if isinstance(content, list) and len(content) > 0:
                text = content[0].get("text", "")
                if "```json" in text:
                    json_str = text.split("```json")[1].split("```")[0].strip()
                elif "```" in text:
                    json_str = text.split("```")[1].split("```")[0].strip()
                else:
                    json_str = text
                
                return json.loads(json_str)
            
            raise ValueError("No content in LLM response")
        except Exception as e:
            # NO FALLBACK - LLM must succeed
            raise Exception(f"Vulnerability analysis failed: {str(e)}. Cannot determine if test revealed a vulnerability.")
    
    async def _generate_final_report(
        self, tool_name: str, results: List[Dict[str, Any]], capability_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate final security report"""
        
        vulnerabilities = [r for r in results if r.get('analysis', {}).get('is_vulnerable')]
        
        return {
            "tool_name": tool_name,
            "total_tests": len(results),
            "vulnerabilities_found": len(vulnerabilities),
            "severity_breakdown": self._count_severities(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "recommendations": self._generate_recommendations(vulnerabilities),
            "overall_risk": self._calculate_overall_risk(vulnerabilities)
        }
    
    def _count_severities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulnerabilities:
            severity = v.get('analysis', {}).get('severity', 'low')
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        recommendations = set()
        for v in vulnerabilities:
            rec = v.get('analysis', {}).get('recommendation')
            if rec:
                recommendations.add(rec)
        return list(recommendations)
    
    def _calculate_overall_risk(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level"""
        if not vulnerabilities:
            return "low"
        
        severities = [v.get('analysis', {}).get('severity', 'low') for v in vulnerabilities]
        if 'critical' in severities:
            return "critical"
        elif 'high' in severities:
            return "high"
        elif 'medium' in severities:
            return "medium"
        return "low"

