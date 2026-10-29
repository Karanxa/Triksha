"""
MCP Client Simulator - Simulates real-world MCP client interactions using an LLM
"""

import json
import asyncio
from typing import Dict, Any, List, Optional, AsyncGenerator
from rich.console import Console
from llm_client import APILLMClient
from mcp_scanner import MCPScanner


class MCPClientSimulator:
    """Simulates a real MCP client using LLM LLM for reasoning"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.llm_client = APILLMClient(console=self.console)
        self.scanner = MCPScanner(console=self.console, enable_llm_analysis=False)
    
    async def simulate_interaction(
        self,
        server_url: str,
        server_type: str,
        user_prompt: str,
        tools: List[Dict[str, Any]],
        conversation_history: List[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Simulate a client interaction where LLM decides which tool to call
        
        Args:
            server_url: MCP server URL
            server_type: Server type (http/sse)
            user_prompt: User's natural language request
            tools: Available tools from the MCP server
            conversation_history: Previous messages in the conversation
            headers: Optional headers for MCP connection
        """
        
        yield {"type": "thinking", "data": {"message": "🤔 Analyzing your request..."}}
        
        # Build tool descriptions for the LLM
        tool_descriptions = self._format_tools_for_llm(tools)
        
        # Build conversation context
        history_context = self._format_conversation_history(conversation_history or [])
        
        # Step 1: Ask LLM to decide what to do
        yield {"type": "thinking", "data": {"message": "🧠 Deciding which tool to use..."}}
        
        decision = await self._decide_action(user_prompt, tool_descriptions, history_context)
        
        if decision.get("action") == "respond":
            # No tool needed, just respond
            yield {
                "type": "complete",
                "data": {"message": decision.get("response", "I don't have a suitable tool for that request.")}
            }
            return
        
        if decision.get("action") == "call_tool":
            tool_name = decision.get("tool_name")
            arguments = decision.get("arguments", {})
            
            # Yield tool call event
            yield {
                "type": "tool_call",
                "data": {
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "reasoning": decision.get("reasoning", "")
                }
            }
            
            # Step 2: Execute the tool
            yield {"type": "thinking", "data": {"message": f"⚡ Calling {tool_name}..."}}
            
            try:
                server_config = {
                    "type": server_type,
                    "url": server_url,
                    "headers": headers or {}
                }
                
                result = await self._execute_tool(server_config, tool_name, arguments)
                
                yield {
                    "type": "tool_result",
                    "data": {
                        "tool_name": tool_name,
                        "result": result,
                        "success": not result.get("isError", False)
                    }
                }
                
                # Step 3: Have LLM interpret the result
                yield {"type": "thinking", "data": {"message": "📝 Interpreting results..."}}
                
                final_response = await self._interpret_result(
                    user_prompt, tool_name, arguments, result
                )
                
                yield {
                    "type": "complete",
                    "data": {"message": final_response}
                }
                
            except Exception as e:
                yield {
                    "type": "tool_result",
                    "data": {
                        "tool_name": tool_name,
                        "result": {"error": str(e)},
                        "success": False
                    }
                }
                
                yield {
                    "type": "complete",
                    "data": {"message": f"I tried to use the {tool_name} tool but encountered an error: {str(e)}"}
                }
    
    def _format_tools_for_llm(self, tools: List[Dict[str, Any]]) -> str:
        """Format tools into a clear description for the LLM"""
        if not tools:
            return "No tools available."
        
        descriptions = []
        for tool in tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "No description")
            schema = tool.get("input_schema", {})
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            
            params = []
            for param_name, param_info in properties.items():
                param_type = param_info.get("type", "any")
                param_desc = param_info.get("description", "")
                req_marker = "*" if param_name in required else ""
                params.append(f"  - {param_name}{req_marker} ({param_type}): {param_desc}")
            
            tool_desc = f"**{name}**: {desc}"
            if params:
                tool_desc += "\n  Parameters:\n" + "\n".join(params)
            descriptions.append(tool_desc)
        
        return "\n\n".join(descriptions)
    
    def _format_conversation_history(self, history: List[Dict[str, Any]]) -> str:
        """Format conversation history for context"""
        if not history:
            return ""
        
        formatted = []
        for msg in history[-10:]:  # Last 10 messages for context
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if role == "user":
                formatted.append(f"User: {content}")
            elif role == "assistant":
                formatted.append(f"Assistant: {content}")
            elif role == "tool":
                formatted.append(f"[Tool {msg.get('tool_name', 'unknown')} was called]")
        
        return "\n".join(formatted)
    
    async def _decide_action(
        self, user_prompt: str, tool_descriptions: str, history_context: str
    ) -> Dict[str, Any]:
        """Use LLM to decide what action to take"""
        
        prompt = f"""You are an AI assistant with access to MCP (Model Context Protocol) tools.

AVAILABLE TOOLS:
{tool_descriptions}

{f"CONVERSATION HISTORY:{chr(10)}{history_context}{chr(10)}" if history_context else ""}
USER REQUEST: {user_prompt}

TASK: Decide how to respond to the user's request.

If a tool can help fulfill the request:
1. Choose the most appropriate tool
2. Determine the correct arguments based on the user's request
3. Return a tool call

If no tool is needed or available:
1. Respond directly to the user

Return JSON (no markdown):
{{
  "action": "call_tool" or "respond",
  "tool_name": "tool_name_if_calling",
  "arguments": {{"param": "value"}},
  "reasoning": "Why you chose this action",
  "response": "Direct response if not calling a tool"
}}

Decide now:"""
        
        try:
            response = await self.llm_client.generate_content(prompt)
            # generate_content returns a string directly
            if isinstance(response, str):
                return self._extract_json(response)
            
            return {"action": "respond", "response": "I couldn't process your request."}
            
        except Exception as e:
            self.console.print(f"[red]Decision error: {e}[/]")
            return {"action": "respond", "response": f"Error processing request: {str(e)}"}
    
    async def _execute_tool(
        self, server_config: Dict[str, Any], tool_name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a tool on the MCP server"""
        
        timeout = 30
        async with self.scanner._get_client(server_config, timeout) as (read, write):
            from mcp import ClientSession
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
                
                # Serialize result
                serialized_content = []
                for item in result.content:
                    if hasattr(item, 'model_dump'):
                        serialized_content.append(item.model_dump())
                    elif hasattr(item, 'dict'):
                        serialized_content.append(item.dict())
                    elif hasattr(item, 'text'):
                        serialized_content.append({"type": "text", "text": item.text})
                    else:
                        serialized_content.append({"text": str(item)})
                
                return {
                    "content": serialized_content,
                    "isError": getattr(result, 'isError', False)
                }
    
    async def _interpret_result(
        self, user_prompt: str, tool_name: str, arguments: Dict[str, Any], result: Dict[str, Any]
    ) -> str:
        """Have LLM interpret the tool result for the user"""
        
        prompt = f"""You are an AI assistant. You just called a tool to help the user.

USER'S ORIGINAL REQUEST: {user_prompt}

TOOL CALLED: {tool_name}
ARGUMENTS USED: {json.dumps(arguments)}

TOOL RESULT:
{json.dumps(result, indent=2)}

TASK: Provide a helpful, natural language response to the user based on the tool result.
- Be concise but informative
- If there was an error, explain what went wrong
- If successful, summarize the key information from the result

Your response:"""
        
        try:
            response = await self.llm_client.generate_content(prompt)
            # generate_content returns a string directly
            if isinstance(response, str) and response.strip():
                return response.strip()
            
            return "I received a response from the tool but couldn't interpret it."
            
        except Exception as e:
            return f"I got results from {tool_name} but encountered an error interpreting them: {str(e)}"
    
    def _extract_json(self, text: str) -> Dict[str, Any]:
        """Extract JSON from LLM response"""
        import re
        
        # Try direct parse
        try:
            return json.loads(text)
        except:
            pass
        
        # Try extracting from code blocks
        if "```json" in text:
            json_str = text.split("```json")[1].split("```")[0].strip()
            return json.loads(json_str)
        elif "```" in text:
            json_str = text.split("```")[1].split("```")[0].strip()
            return json.loads(json_str)
        
        # Try finding JSON object
        match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
        
        return {"action": "respond", "response": text}



    async def run_triksha_agent(
        self,
        server_url: str,
        server_type: str,
        tools: List[Dict[str, Any]],
        server_context: Dict[str, Any] = None,
        headers: Optional[Dict[str, str]] = None,
        max_turns: int = 10
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Fire Triksha Agent - Multi-turn autonomous security assessment.
        
        The agent simulates an AI security engineer:
        1. Analyzes available tools and their potential vulnerabilities
        2. Plans attack sequence based on security knowledge
        3. Executes attacks via tool calls
        4. Analyzes responses for vulnerabilities  
        5. Iterates with new attack vectors based on results
        """
        from mcp_attack_knowledge import MCPAttackKnowledgeBase
        
        yield {"type": "thinking", "data": {"message": "Starting security assessment..."}}
        
        # Initialize attack knowledge base
        knowledge_base = MCPAttackKnowledgeBase()
        
        # Initialize tracking
        vulnerabilities_found = []
        tests_performed = []
        tools_tested = set()
        conversation_memory = []
        
        # Format tools and context for the agent
        tool_descriptions = self._format_tools_for_llm(tools)
        context_summary = self._format_server_context(server_context or {})
        attack_knowledge = self._format_attack_knowledge_from_class(knowledge_base, tools)
        
        yield {"type": "thinking", "data": {"message": f"Found {len(tools)} tool(s) to analyze"}}
        
        # Step 1: Generate contextual attacks using MCP Contextual Attacker
        from mcp_contextual_attacker import MCPContextualAttacker
        attacker = MCPContextualAttacker(console=self.console)
        
        yield {"type": "thinking", "data": {"message": "Generating contextual test cases..."}}
        
        contextual_attacks = await attacker.generate_contextual_attacks(
            tools=tools,
            server_context=server_context,
            security_findings=server_context.get("security_findings", []),
            num_attacks_per_tool=3
        )
        
        # Convert to attack plan format
        attack_plan = []
        for attack in contextual_attacks:
            attack_plan.append({
                "tool_name": attack.get("tool_name"),
                "attack_type": attack.get("attack_type"),
                "payload": attack.get("description"),
                "reasoning": attack.get("expected_impact"),
                "precomputed_arguments": attack.get("arguments")  # Use pre-generated arguments
            })
        
        yield {"type": "thinking", "data": {"message": f"Ready to run {len(attack_plan)} tests"}}
        
        # Execute multi-turn testing
        for turn in range(1, min(len(attack_plan) + 1, max_turns + 1)):
            yield {"type": "turn_complete", "data": {"turn": turn, "total_turns": len(attack_plan)}}
            
            if turn > len(attack_plan):
                break
                
            attack = attack_plan[turn - 1]
            target_tool = attack.get("tool_name", "unknown")
            attack_type = attack.get("attack_type", "security_test")
            reasoning = attack.get("reasoning", "") or attack.get("expected_impact", "")
            
            tools_tested.add(target_tool)
            
            # Find the actual tool definition
            tool_def = next((t for t in tools if t.get("name") == target_tool), None)
            if not tool_def:
                yield {
                    "type": "analysis", 
                    "data": {
                        "message": f"Tool '{target_tool}' not found, skipping",
                        "vulnerability_found": False,
                        "severity": None
                    }
                }
                continue
            
            # Get actual payload arguments
            if attack.get("precomputed_arguments"):
                arguments = attack["precomputed_arguments"]
            else:
                arguments = await self._generate_attack_arguments(
                    tool_def, attack_type, attack.get("description", ""), conversation_memory
                )
            
            # Format the actual payload for display - show clean values
            if arguments:
                # If single argument, show just the value
                if len(arguments) == 1:
                    payload_display = str(list(arguments.values())[0])
                else:
                    # Multiple arguments - show as param: value pairs
                    payload_display = " | ".join([f"{k}: {v}" for k, v in arguments.items()])
            else:
                payload_display = "No arguments"
            
            # Emit the attack with ACTUAL payload
            yield {
                "type": "attack_prompt",
                "data": {
                    "prompt": payload_display,
                    "attack_type": attack_type,
                    "target_tool": target_tool,
                    "reasoning": reasoning
                }
            }
            
            # Emit tool call
            yield {
                "type": "tool_call",
                "data": {
                    "tool_name": target_tool,
                    "arguments": arguments,
                    "status": "calling"
                }
            }
            
            # Execute the attack
            try:
                server_config = {
                    "type": server_type,
                    "url": server_url,
                    "headers": headers or {}
                }
                
                result = await self._execute_tool(server_config, target_tool, arguments)
                
                yield {
                    "type": "tool_result",
                    "data": {
                        "tool_name": target_tool,
                        "result": result,
                        "success": not result.get("isError", False)
                    }
                }
                
                # Analyze the result for vulnerabilities
                analysis = await self._analyze_for_vulnerabilities(
                    target_tool, attack_type, arguments, result, conversation_memory
                )
                
                tests_performed.append({
                    "tool": target_tool,
                    "attack_type": attack_type,
                    "arguments": arguments,
                    "result": result,
                    "analysis": analysis
                })
                
                # Update conversation memory
                conversation_memory.append({
                    "turn": turn,
                    "tool": target_tool,
                    "attack_type": attack_type,
                    "result_summary": str(result)[:500],
                    "vulnerability": analysis.get("vulnerability_found", False)
                })
                
                # Emit single result - either vulnerability or clean analysis
                if analysis.get("vulnerability_found"):
                    vuln_data = {
                        "vulnerability_type": analysis.get("vulnerability_type", attack_type),
                        "severity": analysis.get("severity", "medium"),
                        "details": analysis.get("explanation", "Security issue detected"),
                        "recommendation": analysis.get("recommendation", "Review this functionality")
                    }
                    vulnerabilities_found.append(vuln_data)
                    yield {"type": "vulnerability", "data": vuln_data}
                else:
                    yield {
                        "type": "analysis",
                        "data": {
                            "message": analysis.get("explanation", "No issues detected"),
                            "vulnerability_found": False,
                            "severity": None
                        }
                    }
                
            except Exception as e:
                # Error might indicate vulnerability (e.g., crash = potential DoS)
                if "timeout" in str(e).lower() or "overflow" in str(e).lower():
                    vuln_data = {
                        "vulnerability_type": "Denial of Service",
                        "severity": "high",
                        "details": f"Tool crashed or timed out: {str(e)}",
                        "recommendation": "Implement proper input validation and resource limits"
                    }
                    vulnerabilities_found.append(vuln_data)
                    yield {"type": "vulnerability", "data": vuln_data}
                else:
                    yield {
                        "type": "analysis",
                        "data": {
                            "message": f"Test error: {str(e)[:100]}",
                            "vulnerability_found": False,
                            "severity": None
                        }
                    }
        
        # Build findings for database storage
        db_findings = []
        for test in tests_performed:
            db_findings.append({
                "tool_name": test.get("tool", ""),
                "attack_type": test.get("attack_type", ""),
                "payload": json.dumps(test.get("arguments", {})),
                "response": json.dumps(test.get("result", {}))[:2000],  # Limit size
                "vulnerability_found": test.get("analysis", {}).get("vulnerability_found", False),
                "vulnerability_type": test.get("analysis", {}).get("vulnerability_type"),
                "severity": test.get("analysis", {}).get("severity"),
                "details": test.get("analysis", {}).get("explanation", ""),
                "recommendation": test.get("analysis", {}).get("recommendation", "")
            })
        
        # Final summary with findings for DB
        yield {
            "type": "complete",
            "data": {
                "message": f"Security assessment complete. Tested {len(tools_tested)} tools across {len(tests_performed)} scenarios.",
                "summary": {
                    "total_tests": len(tests_performed),
                    "vulnerabilities": len(vulnerabilities_found),
                    "tools_tested": len(tools_tested),
                    "vulnerability_list": vulnerabilities_found
                },
                "findings_for_db": db_findings  # Include for frontend to save
            }
        }
    
    def _format_server_context(self, context: Dict[str, Any]) -> str:
        """Format server context for the agent"""
        parts = []
        if context.get("server_name"):
            parts.append(f"Server: {context['server_name']}")
        if context.get("security_findings"):
            findings = context["security_findings"][:5]  # Top 5
            finding_strs = []
            for f in findings:
                if isinstance(f, dict):
                    finding_strs.append(str(f.get('evidence', ''))[:50])
                else:
                    finding_strs.append(str(f)[:50])
            parts.append(f"Known security findings: {', '.join(finding_strs)}")
        if context.get("capability_concerns"):
            concerns = context["capability_concerns"][:3]
            concern_strs = []
            for c in concerns:
                if isinstance(c, dict):
                    concern_strs.append(str(c.get('concern', ''))[:50])
                else:
                    concern_strs.append(str(c)[:50])
            parts.append(f"Capability concerns: {', '.join(concern_strs)}")
        return "\n".join(parts) if parts else "No additional context available."
    
    def _format_attack_knowledge(self, knowledge: Dict[str, Any]) -> str:
        """Format attack knowledge base for the LLM"""
        vectors = []
        for attack_type, attack_data in list(knowledge.items())[:8]:  # Top 8 attack types
            desc = attack_data.get("description", "")
            techniques = attack_data.get("techniques", [])[:3]
            vectors.append(f"- {attack_type}: {desc[:100]}. Techniques: {', '.join(techniques)}")
        return "\n".join(vectors)
    
    def _format_attack_knowledge_from_class(self, knowledge_base: 'MCPAttackKnowledgeBase', tools: List[Dict]) -> str:
        """Format attack knowledge from the MCPAttackKnowledgeBase class"""
        all_attacks = []
        
        # Get relevant attacks for each tool
        for tool in tools[:3]:  # Top 3 tools
            tool_name = tool.get("name", "")
            description = tool.get("description", "")
            params = list(tool.get("input_schema", {}).get("properties", {}).keys())
            relevant = knowledge_base.get_relevant_attacks(tool_name, description, params)
            all_attacks.extend(relevant)
        
        # Deduplicate and format
        seen = set()
        formatted = []
        for attack in all_attacks:
            if attack.id not in seen:
                seen.add(attack.id)
                payloads = [p["value"] for p in attack.payloads[:2]]
                formatted.append(f"- **{attack.name}** ({attack.severity}): {attack.description[:80]}. Example payloads: {payloads}")
        
        return "\n".join(formatted[:10])
    
    async def _plan_attack_sequence(
        self, tool_descriptions: str, context: str, attack_knowledge: str
    ) -> List[Dict[str, Any]]:
        """Use LLM to plan a multi-turn attack sequence"""
        
        prompt = f"""You are Triksha, an elite AI security agent specializing in MCP (Model Context Protocol) security testing.

AVAILABLE TOOLS:
{tool_descriptions}

SERVER CONTEXT:
{context}

ATTACK KNOWLEDGE BASE:
{attack_knowledge}

MISSION: Create a comprehensive security test plan. Think like a professional penetration tester.

For each test, consider:
1. Which tool is most likely to have vulnerabilities based on its functionality
2. What attack vector would be most effective
3. What specific payload would reveal the vulnerability
4. How the test relates to real-world attack scenarios

Return a JSON array of 5-8 targeted tests:
```json
[
  {{
    "tool_name": "exact_tool_name",
    "attack_type": "injection|path_traversal|ssrf|data_exfiltration|privilege_escalation|dos|info_disclosure|auth_bypass",
    "payload": "The actual malicious input or prompt that would trigger the vulnerability",
    "reasoning": "Why this attack matters and what it could reveal"
  }}
]
```

Be creative and thorough. Generate realistic, contextual payloads that would actually test for vulnerabilities.
Do NOT use generic placeholders - use actual attack payloads."""

        try:
            response = await self.llm_client.generate_content(prompt)
            if isinstance(response, str):
                plan = self._extract_json_array(response)
                if plan:
                    return plan
                raise Exception("LLM did not return valid attack plan JSON")
        except Exception as e:
            self.console.print(f"[red]Attack planning error: {e}[/]")
            self.console.print(f"[yellow]AI service temporarily unavailable, using basic test plan[/]")
            # Return a minimal test plan
            return [{"tool_name": tools[0].get("name") if tools else "unknown", "attack_type": "basic_test", "description": "Basic security validation", "arguments": {}}] if tools else []
    
    async def _generate_attack_arguments(
        self, tool_def: Dict[str, Any], attack_type: str, payload: str, memory: List[Dict]
    ) -> Dict[str, Any]:
        """Generate attack arguments for the tool"""
        
        schema = tool_def.get("input_schema", {})
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        
        prompt = f"""Generate attack arguments for security testing.

TOOL: {tool_def.get("name")}
DESCRIPTION: {tool_def.get("description")}
ATTACK TYPE: {attack_type}
PAYLOAD/PROMPT: {payload}

TOOL PARAMETERS:
{json.dumps(properties, indent=2)}

Required fields: {required}

Previous test results context:
{json.dumps(memory[-3:], indent=2) if memory else 'First test'}

Return ONLY a JSON object with the attack arguments. Make the values actually malicious/testing payloads based on the attack type.

Example for injection: {{"query": "'; DROP TABLE users; --"}}
Example for path traversal: {{"path": "../../../../etc/passwd"}}

Your attack arguments:"""

        try:
            response = await self.llm_client.generate_content(prompt)
            if isinstance(response, str):
                args = self._extract_json(response)
                if args and isinstance(args, dict):
                    # Remove any meta fields
                    args.pop("action", None)
                    args.pop("response", None)
                    return args
        except Exception as e:
            # Graceful fallback - use basic test values
            self.console.print(f"[yellow]Using default test values[/]")
            args = {}
            for param in required:
                args[param] = "test_value"
            return args
    
    async def _analyze_for_vulnerabilities(
        self, tool_name: str, attack_type: str, arguments: Dict, result: Dict, memory: List
    ) -> Dict[str, Any]:
        """Analyze tool response for security vulnerabilities"""
        
        result_str = json.dumps(result, indent=2)[:2000]  # Limit size
        
        prompt = f"""You are a security analyst reviewing the result of a penetration test.

TOOL TESTED: {tool_name}
ATTACK TYPE: {attack_type}
ARGUMENTS SENT: {json.dumps(arguments)}
RESPONSE RECEIVED:
{result_str}

Analyze this response for security vulnerabilities. Consider:
1. Did the tool process malicious input without sanitization?
2. Are there signs of injection (reflected input, unexpected behavior)?
3. Did it reveal sensitive information (paths, credentials, internal data)?
4. Did it indicate access to resources it shouldn't have?
5. Did it return error messages that leak implementation details?

Return JSON:
{{
  "vulnerability_found": true/false,
  "vulnerability_type": "type if found",
  "severity": "critical/high/medium/low",
  "explanation": "Brief analysis of what happened",
  "details": "Specific evidence of the vulnerability",
  "recommendation": "How to fix this issue"
}}"""

        try:
            response = await self.llm_client.generate_content(prompt)
            if isinstance(response, str):
                analysis = self._extract_json(response)
                if analysis and isinstance(analysis, dict):
                    return analysis
        except Exception as e:
            # Graceful fallback - basic result inspection
            self.console.print(f"[yellow]Using basic analysis[/]")
            result_str = str(result).lower()
            suspicious = any(word in result_str for word in ["error", "exception", "denied", "unauthorized", "password", "secret"])
            return {
                "vulnerability_found": suspicious,
                "vulnerability_type": attack_type if suspicious else None,
                "severity": "medium" if suspicious else None,
                "explanation": "Suspicious patterns detected in response" if suspicious else "No obvious issues detected",
                "details": "",
                "recommendation": "Manual review recommended"
            }
    
    async def _adapt_attack_plan(
        self, remaining_plan: List[Dict], memory: List[Dict], attack_knowledge: str
    ) -> Optional[List[Dict]]:
        """Adapt the attack plan based on what we've learned"""
        
        prompt = f"""Based on security testing results, adapt the remaining attack plan.

TESTING MEMORY (recent results):
{json.dumps(memory[-5:], indent=2)}

REMAINING PLANNED TESTS:
{json.dumps(remaining_plan[:3], indent=2)}

ATTACK KNOWLEDGE:
{attack_knowledge}

Should we:
1. Continue with the current plan
2. Add new tests based on discovered patterns
3. Focus on areas that showed weakness

Return JSON array of adapted tests (same format as before), or null to continue unchanged."""

        try:
            response = await self.llm_client.generate_content(prompt)
            if isinstance(response, str):
                if "null" in response.lower() or "continue" in response.lower():
                    return None
                adapted = self._extract_json_array(response)
                if adapted:
                    return adapted
        except:
            pass
        return None
    

    def _extract_json_array(self, text: str) -> Optional[List]:
        """Extract JSON array from LLM response"""
        import re
        
        # Try direct parse
        try:
            result = json.loads(text)
            if isinstance(result, list):
                return result
        except:
            pass
        
        # Try extracting from code blocks
        if "```json" in text:
            json_str = text.split("```json")[1].split("```")[0].strip()
            return json.loads(json_str)
        elif "```" in text:
            json_str = text.split("```")[1].split("```")[0].strip()
            result = json.loads(json_str)
            if isinstance(result, list):
                return result
        
        # Try finding JSON array
        match = re.search(r'\[[\s\S]*\]', text)
        if match:
            return json.loads(match.group())
        
        return None
