"""
MCP Scanner Service for Triksha
Scans MCP (Model Context Protocol) server configurations with security analysis
"""

import asyncio
import logging
import ssl
import hashlib
from contextlib import asynccontextmanager
from typing import Dict, Any, List, Optional, Literal
import pyjson5
import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from pydantic import BaseModel, Field
from rich.console import Console

# Import security detectors
from mcp_detectors import (
    detect_hidden_instructions,
    detect_exfiltration_channels,
    detect_tool_shadowing,
    detect_sensitive_file_access,
    detect_cross_origin_violations,
)
from mcp_detectors.capability_analysis import (
    calculate_comprehensive_security_score,
    analyze_tool_capabilities,
    analyze_resource_capabilities,
    analyze_prompt_capabilities
)

# Import LLM-based threat analyzer
try:
    from mcp_detectors.Stat_analyser import (
        MCPThreatAnalyzer,
        LLMConfig,
        LLMSeverityLevel,
        LLMAnalysisResult
    )
    STAT_ANALYSER_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Stat_analyser not available: {e}. LLM-based analysis will be skipped.")
    STAT_ANALYSER_AVAILABLE = False

# Set up logger
logger = logging.getLogger(__name__)


class RemoteServerConfig(BaseModel):
    """Remote MCP server configuration (HTTP or SSE)"""
    type: Literal["http", "sse"]
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)


class StdioServerConfig(BaseModel):
    """STDIO MCP server configuration"""
    type: Literal["stdio"] = "stdio"
    command: str
    args: List[str] = Field(default_factory=list)
    env: Optional[Dict[str, str]] = None


class MCPScanResult(BaseModel):
    """Result of scanning an MCP server with security analysis"""
    server_name: str
    server_type: str
    status: Literal["success", "error", "timeout"]
    error_message: Optional[str] = None
    
    # Server metadata
    protocol_version: Optional[str] = None
    server_info: Optional[Dict[str, Any]] = None
    capabilities: Optional[Dict[str, Any]] = None
    server_url: Optional[str] = None  # The URL/endpoint of the MCP server
    
    # Discovered entities
    tools: List[Dict[str, Any]] = Field(default_factory=list)
    prompts: List[Dict[str, Any]] = Field(default_factory=list)
    resources: List[Dict[str, Any]] = Field(default_factory=list)
    resource_templates: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Security analysis results
    security_findings: List[Dict[str, Any]] = Field(default_factory=list)  # Pattern-based findings
    entity_changes: List[Dict[str, Any]] = Field(default_factory=list)  # For poisoning detection
    security_score: Optional[int] = None  # 0-100, 100 = most secure
    
    # Capability-based analysis results
    capability_concerns: List[str] = Field(default_factory=list)  # List of security concerns from capability analysis
    detected_capabilities: List[str] = Field(default_factory=list)  # List of capabilities detected (file_system_access, network_access, etc.)
    risk_breakdown: Optional[Dict[str, int]] = None  # {critical: X, high: Y, medium: Z, low: W}
    
    # LLM-based analysis results
    llm_analysis_results: Optional[Dict[str, Any]] = None  # Results from Stat_analyser
    llm_analysis_enabled: bool = True  # Flag to enable/disable LLM analysis
    
    # Server summary
    server_summary: Optional[str] = None  # AI-generated summary of the MCP server's purpose and capabilities


def _unwrap_error(exc: Exception) -> str:
    """Extract a human-readable message from exceptions, including anyio ExceptionGroups
    that the MCP streamable-HTTP client wraps real HTTP errors in."""
    import httpx

    # Walk an ExceptionGroup tree to find the first meaningful leaf
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            msg = _unwrap_error(sub)
            if msg:
                return msg
        # All children returned empty — fall through to generic handling below

    # httpx HTTP status errors → short "HTTP 401 Unauthorized"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code} {exc.response.reason_phrase}"

    # httpx connectivity errors (DNS, refused, etc.)
    if isinstance(exc, httpx.ConnectTimeout):
        return "Connection timed out"
    if isinstance(exc, httpx.ConnectError):
        return "Connection refused"
    if isinstance(exc, httpx.RemoteProtocolError):
        return "Remote protocol error"

    msg = str(exc).strip()
    # Suppress the generic ExceptionGroup wrapper text; prefer its inner message
    if msg.startswith("unhandled errors in a TaskGroup"):
        # Last resort: return the type name so the caller never gets ""
        return f"{type(exc).__name__}"
    return msg or f"{type(exc).__name__}"


class MCPScanner:
    """Scanner for MCP servers"""
    
    def __init__(self, console: Optional[Console] = None, enable_llm_analysis: bool = True):
        self.console = console or Console()
        self.enable_llm_analysis = enable_llm_analysis and STAT_ANALYSER_AVAILABLE
        self.llm_analyzer = None
        
        # Initialize LLM analyzer if available
        if self.enable_llm_analysis:
            try:
                config = LLMConfig(
                    min_severity=LLMSeverityLevel.LOW,  # Report all findings
                    temperature=0.1,  # Low temperature for consistent results
                    max_output_tokens=2048
                )
                self.llm_analyzer = MCPThreatAnalyzer(config, console=self.console)
                self.console.print("[green]✓ LLM-based threat analyzer initialized[/]")
            except Exception as e:
                logger.warning(f"Failed to initialize LLM analyzer: {e}")
                self.enable_llm_analysis = False
                self.llm_analyzer = None
    
    @asynccontextmanager
    async def _get_client(
        self,
        server_config: Dict[str, Any],
        timeout: int = 30
    ):
        """Create appropriate client based on server type"""
        server_type = server_config.get("type", "http")
        
        # Monkey-patch httpx to disable SSL verification globally for this session
        # This is needed because MCP client creates its own httpx clients internally
        original_async_client = httpx.AsyncClient
        
        def patched_async_client(*args, **kwargs):
            # Force verify=False for all httpx clients created
            kwargs['verify'] = False
            return original_async_client(*args, **kwargs)
        
        # Temporarily replace httpx.AsyncClient
        httpx.AsyncClient = patched_async_client
        
        try:
            if server_type == "sse":
                async with sse_client(
                    url=server_config["url"],
                    headers=server_config.get("headers", {}),
                    timeout=timeout
                ) as (read, write):
                    yield read, write
                    
            elif server_type == "http":
                async with streamablehttp_client(
                    url=server_config["url"],
                    headers=server_config.get("headers", {}),
                    timeout=timeout
                ) as (read, write, _):
                    yield read, write
                    
            elif server_type == "stdio":
                _ALLOWED_STDIO_COMMANDS = {"npx", "node", "python", "python3", "uvx", "uv", "deno", "bun"}
                raw_cmd = server_config["command"]
                # Only the base executable name (no path components) may be used
                import os as _os
                cmd_base = _os.path.basename(raw_cmd)
                if cmd_base not in _ALLOWED_STDIO_COMMANDS:
                    raise ValueError(f"MCP stdio command not allowed: {cmd_base!r}")
                server_params = StdioServerParameters(
                    command=cmd_base,
                    args=server_config.get("args", []),
                    env=server_config.get("env")
                )
                async with stdio_client(server_params) as (read, write):
                    yield read, write
            else:
                raise ValueError(f"Unsupported server type: {server_type}")
        finally:
            # Restore original httpx.AsyncClient
            httpx.AsyncClient = original_async_client
    
    async def scan_server(
        self,
        server_name: str,
        server_config: Dict[str, Any],
        timeout: int = 30,
        scan_id: str = None,
        check_inventory: bool = True
    ) -> MCPScanResult:
        """Scan a single MCP server
        
        Args:
            server_name: Name of the server
            server_config: Server configuration dict
            timeout: Timeout in seconds
            
        Returns:
            MCPScanResult with scan results
        """
        self.console.print(f"[cyan]Scanning MCP server: {server_name}[/]")
        
        # Check inventory if enabled
        inventory_info = None
        change_detected = False
        if check_inventory:
            try:
                from db_factory import get_database
                db = get_database()  # PostgreSQL or SQLite
                
                # Generate hash for this server config
                server_config_hash = db.generate_mcp_hash(server_config)
                
                # Check if already in inventory
                inventory_info = db.check_mcp_inventory(server_config_hash)
                
                if inventory_info:
                    self.console.print(f"[green]✓ MCP server '{server_name}' found in inventory (scanned {inventory_info['scan_count']} times)[/]")
                    self.console.print(f"[dim]First seen: {inventory_info['first_seen']}, Last seen: {inventory_info['last_seen']}[/]")
                    
                    # Check if config has changed (compare current hash with stored hash)
                    # If they're different, it means the config changed
                    if inventory_info.get('server_config_hash') != server_config_hash:
                        change_detected = True
                        self.console.print(f"[yellow]⚠ Configuration change detected for '{server_name}'[/]")
                        self.console.print(f"[dim]Previous hash: {inventory_info.get('server_config_hash', 'N/A')[:16]}...[/]")
                        self.console.print(f"[dim]Current hash: {server_config_hash[:16]}...[/]")
                    else:
                        self.console.print(f"[dim]No configuration changes detected[/]")
                else:
                    self.console.print(f"[cyan]New MCP server '{server_name}' - adding to inventory[/]")
                    
            except Exception as e:
                self.console.print(f"[yellow]Warning: Could not check inventory: {e}[/]")
        
        result = MCPScanResult(
            server_name=server_name,
            server_type=server_config.get("type", "unknown"),
            server_url=server_config.get("url"),  # Store the MCP server URL
            status="error"
        )
        
        try:
            async with asyncio.timeout(timeout):
                async with self._get_client(server_config, timeout) as (read, write):
                    async with ClientSession(read, write) as session:
                        # Initialize connection
                        self.console.print(f"[cyan]Initializing connection to {server_name}...[/]")
                        init_result = await session.initialize()
                        
                        # Extract metadata
                        result.protocol_version = init_result.protocolVersion
                        result.server_info = {
                            "name": init_result.serverInfo.name,
                            "version": init_result.serverInfo.version
                        }
                        result.capabilities = {
                            "prompts": bool(init_result.capabilities.prompts),
                            "resources": bool(init_result.capabilities.resources),
                            "tools": bool(init_result.capabilities.tools),
                            "logging": bool(init_result.capabilities.logging)
                        }
                        
                        # Fetch tools if supported
                        if init_result.capabilities.tools:
                            try:
                                self.console.print(f"[cyan]Fetching tools from {server_name}...[/]")
                                tools_response = await session.list_tools()
                                result.tools = [
                                    {
                                        "name": tool.name,
                                        "description": tool.description,
                                        "input_schema": tool.inputSchema
                                    }
                                    for tool in tools_response.tools
                                ]
                                self.console.print(f"[green]Found {len(result.tools)} tools[/]")
                            except Exception as e:
                                err = _unwrap_error(e)
                                self.console.print(f"[red]Failed to fetch tools from {server_name}: {err}[/]")
                                if not result.error_message:
                                    result.error_message = f"list_tools failed: {err}"

                        # Fetch prompts if supported
                        if init_result.capabilities.prompts:
                            try:
                                self.console.print(f"[cyan]Fetching prompts from {server_name}...[/]")
                                prompts_response = await session.list_prompts()
                                result.prompts = [
                                    {
                                        "name": prompt.name,
                                        "description": prompt.description,
                                        "arguments": [
                                            {"name": arg.name, "description": arg.description, "required": arg.required}
                                            for arg in (prompt.arguments or [])
                                        ]
                                    }
                                    for prompt in prompts_response.prompts
                                ]
                                self.console.print(f"[green]Found {len(result.prompts)} prompts[/]")
                            except Exception as e:
                                err = _unwrap_error(e)
                                self.console.print(f"[red]Failed to fetch prompts from {server_name}: {err}[/]")
                                if not result.error_message:
                                    result.error_message = f"list_prompts failed: {err}"

                        # Fetch resources if supported
                        if init_result.capabilities.resources:
                            try:
                                self.console.print(f"[cyan]Fetching resources from {server_name}...[/]")
                                resources_response = await session.list_resources()
                                result.resources = [
                                    {
                                        "uri": resource.uri,
                                        "name": resource.name,
                                        "description": resource.description,
                                        "mime_type": resource.mimeType
                                    }
                                    for resource in resources_response.resources
                                ]
                                self.console.print(f"[green]Found {len(result.resources)} resources[/]")
                            except Exception as e:
                                err = _unwrap_error(e)
                                self.console.print(f"[red]Failed to fetch resources from {server_name}: {err}[/]")
                                if not result.error_message:
                                    result.error_message = f"list_resources failed: {err}"

                            # Fetch resource templates
                            try:
                                templates_response = await session.list_resource_templates()
                                result.resource_templates = [
                                    {
                                        "uri_template": template.uriTemplate,
                                        "name": template.name,
                                        "description": template.description,
                                        "mime_type": template.mimeType
                                    }
                                    for template in templates_response.resourceTemplates
                                ]
                                self.console.print(f"[green]Found {len(result.resource_templates)} resource templates[/]")
                            except Exception as e:
                                err = _unwrap_error(e)
                                self.console.print(f"[red]Failed to fetch resource templates from {server_name}: {err}[/]")
                                if not result.error_message:
                                    result.error_message = f"list_resource_templates failed: {err}"
                        
                        # Determine final status: if we connected & initialized
                        # but every capability fetch failed, mark as error
                        has_any_data = (
                            len(result.tools) > 0 or
                            len(result.prompts) > 0 or
                            len(result.resources) > 0 or
                            len(result.resource_templates) > 0
                        )
                        if result.error_message and not has_any_data:
                            # Connected OK but all fetches failed (e.g. 401 on list_tools)
                            result.status = "error"
                            self.console.print(f"[red]✗ Connected to {server_name} but all capability fetches failed: {result.error_message}[/]")
                        else:
                            result.status = "success"
                            self.console.print(f"[green]✓ Successfully scanned {server_name}[/]")
                        
        except asyncio.TimeoutError:
            result.status = "timeout"
            result.error_message = f"Connection timeout after {timeout} seconds"
            self.console.print(f"[red]✗ Timeout scanning {server_name}[/]")

        except Exception as e:
            result.status = "error"
            # ExceptionGroup from anyio/MCP wraps the real cause — unwrap it
            result.error_message = _unwrap_error(e)
            self.console.print(f"[red]✗ Error scanning {server_name}: {result.error_message}[/]")
            logger.exception(f"Error scanning MCP server {server_name}")
        
        # Generate AI summary if scan was successful
        if result.status == "success":
            try:
                result.server_summary = await self.generate_server_summary(result)
                self.console.print(f"[dim]✓ Generated AI summary for '{server_name}'[/]")
            except Exception as e:
                self.console.print(f"[yellow]Warning: Could not generate server summary: {e}[/]")
        
        # Update inventory after scan (if enabled and scan_id provided)
        if check_inventory and scan_id:
            try:
                from db_factory import get_database
                db = get_database()  # PostgreSQL or SQLite
                
                # Generate hash for this server config
                server_config_hash = db.generate_mcp_hash(server_config)
                
                # Update inventory (only if scan was successful or we want to track all attempts)
                if result.status == "success":
                    db.add_to_mcp_inventory(
                        server_name=server_name,
                        server_config=server_config,
                        server_config_hash=server_config_hash,
                        scan_id=scan_id,
                        change_detected=change_detected
                    )
                    self.console.print(f"[dim]✓ Updated inventory for '{server_name}'[/]")
                    
            except Exception as e:
                self.console.print(f"[yellow]Warning: Could not update inventory: {e}[/]")
        
        return result
    
    def analyze_entity_security(
        self,
        entity: Dict[str, Any],
        entity_type: str,
        server_name: str,
        all_server_names: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Run security detectors on a single entity (tool, prompt, resource).
        
        Returns list of security findings with severity levels.
        """
        findings = []
        description = entity.get("description", "")
        entity_name = entity.get("name", "unnamed")
        
        # Run pattern-based detectors
        detectors = {
            "hidden_instructions": detect_hidden_instructions(description),
            "tool_shadowing": detect_tool_shadowing(description),
            "sensitive_files": detect_sensitive_file_access(description),
            "cross_origin": detect_cross_origin_violations(
                description,
                all_server_names,
                server_name
            )
        }
        
        # Add exfiltration detector for tools (which have input schemas)
        if entity_type == "tool" and "input_schema" in entity:
            detectors["exfiltration"] = detect_exfiltration_channels(entity["input_schema"])
        
        # Process detector results
        for detector_name, result in detectors.items():
            if result.get("detected"):
                matches = result.get("matches", [])
                
                # Determine severity based on detector type and match count
                severity = "low"
                if detector_name in ["hidden_instructions", "exfiltration", "sensitive_files"]:
                    severity = "high" if len(matches) > 2 else "medium"
                elif detector_name in ["tool_shadowing", "cross_origin"]:
                    severity = "medium" if len(matches) > 1 else "low"
                
                # Check if any match has explicit risk_level
                for match in matches:
                    if match.get("risk_level") == "high":
                        severity = "high"
                        break
                
                findings.append({
                    "entity_name": entity_name,
                    "entity_type": entity_type,
                    "detector": detector_name,
                    "severity": severity,
                    "match_count": len(matches),
                    "matches": matches,
                    "summary": f"Found {len(matches)} {detector_name.replace('_', ' ')} pattern(s)"
                })
        
        return findings
    
    def calculate_security_score(self, findings: List[Dict[str, Any]]) -> int:
        """
        Calculate overall security score (0-100) based on findings.
        100 = most secure, 0 = most vulnerable
        """
        if not findings:
            return 100
        
        # Count by severity
        high_count = sum(1 for f in findings if f.get("severity") == "high")
        medium_count = sum(1 for f in findings if f.get("severity") == "medium")
        low_count = sum(1 for f in findings if f.get("severity") == "low")
        
        # Weighted penalty calculation
        penalty = (high_count * 30) + (medium_count * 15) + (low_count * 5)
        
        # Cap at 0
        score = max(0, 100 - penalty)
        
        return score
    
    async def generate_server_summary(self, scan_result: MCPScanResult) -> str:
        """
        Generate a concise summary of the MCP server's purpose and capabilities using the LLM.
        
        Args:
            scan_result: The scan result containing server information
            
        Returns:
            A brief summary string
        """
        try:
            from llm_client import APILLMClient

            # Prepare context about the server
            server_context = {
                "name": scan_result.server_info.get("name") if scan_result.server_info else scan_result.server_name,
                "type": scan_result.server_type,
                "tools_count": len(scan_result.tools),
                "prompts_count": len(scan_result.prompts),
                "resources_count": len(scan_result.resources),
                "tool_names": [tool.get("name") for tool in scan_result.tools[:10]],  # First 10 tools
                "capabilities": list(scan_result.detected_capabilities)[:5] if scan_result.detected_capabilities else []
            }
            
            prompt = f"""Summarize this MCP server in 1-2 sentences focusing on its primary purpose and key capabilities.

Server: {server_context['name']}
Type: {server_context['type']}
Tools: {server_context['tools_count']} (e.g., {', '.join(server_context['tool_names'][:5])})
Prompts: {server_context['prompts_count']}
Resources: {server_context['resources_count']}

Write a brief, professional summary suitable for a security report."""
            
            self.console.print(f"[cyan]Generating AI summary for {server_context['name']}...[/]")
            llm = APILLMClient()
            response = await llm.generate_content(
                prompt=prompt,
                verbose=False
            )
            
            self.console.print(f"[dim]LLM response length: {len(response) if response else 0} chars[/]")
            summary = response.strip() if response else ""
            if summary:
                self.console.print(f"[green]✓ Generated summary: {summary[:100]}...[/]")
                return summary
            else:
                self.console.print(f"[yellow]Empty response from LLM, using fallback[/]")
                return f"MCP server providing {server_context['tools_count']} tools, {server_context['prompts_count']} prompts, and {server_context['resources_count']} resources for AI agents."
                
        except Exception as e:
            self.console.print(f"[red]Failed to generate server summary: {e}[/]")
            logger.exception(f"Error generating server summary")
            # Fallback to basic summary
            return f"MCP server providing {len(scan_result.tools)} tools, {len(scan_result.prompts)} prompts, and {len(scan_result.resources)} resources for AI agents."
    
    async def run_llm_analysis(
        self,
        entities: List[Dict[str, Any]],
        entity_type: str,
        server_name: str
    ) -> Optional[LLMAnalysisResult]:
        """
        Run LLM-based threat analysis on a collection of entities.
        
        Args:
            entities: List of entities (tools, prompts, resources, etc.)
            entity_type: Type of entity being analyzed
            server_name: Name of the server being scanned
            
        Returns:
            LLMAnalysisResult if successful, None if analysis failed or disabled
        """
        if not self.enable_llm_analysis or not self.llm_analyzer or not entities:
            return None
        
        try:
            self.console.print(f"[cyan]Running LLM-based analysis on {len(entities)} {entity_type}(s) from {server_name}...[/]")
            
            # Validate entities before analysis
            if not isinstance(entities, list) or len(entities) == 0:
                logger.warning(f"Invalid entities list for {entity_type}s in {server_name}")
                return None
            
            # Combine all entities of this type into a single analysis
            # This allows the LLM to see the full context
            combined_content = {
                "entity_type": entity_type,
                "server": server_name,
                "entities": entities
            }
            # Run the analysis with timeout protection
            try:
                result = await asyncio.wait_for(
                    self.llm_analyzer.analyze_mcp_content(combined_content),
                    timeout=120  # 2 minute timeout for LLM analysis
                )
            except asyncio.TimeoutError:
                logger.error(f"LLM analysis timeout for {entity_type}s in {server_name}")
                self.console.print(f"[red]✗ LLM analysis timeout for {entity_type}s (exceeded 2 minutes)[/]")
                return None
            except Exception as api_error:
                logger.error(f"LLM API error for {entity_type}s in {server_name}: {str(api_error)}")
                self.console.print(f"[red]✗ LLM API error for {entity_type}s: {str(api_error)}[/]")
                return None
            
            # Validate result
            if not result or not isinstance(result, LLMAnalysisResult):
                logger.warning(f"Invalid LLM analysis result for {entity_type}s in {server_name}")
                return None
            
            # Display results in terminal
            if result.findings:
                self.console.print(f"[yellow]LLM Analysis Results for {entity_type}s:[/]")
                self.console.print(f"  Security Score: [bold]{result.security_score}/100[/]")
                self.console.print(f"  Findings: [bold]{len(result.findings)}[/]")
                
                # Group findings by severity
                critical = [f for f in result.findings if f.severity == "CRITICAL"]
                high = [f for f in result.findings if f.severity == "HIGH"]
                medium = [f for f in result.findings if f.severity == "MEDIUM"]
                low = [f for f in result.findings if f.severity == "LOW"]
                
                if critical:
                    self.console.print(f"  [red]CRITICAL: {len(critical)}[/]")
                if high:
                    self.console.print(f"  [red]HIGH: {len(high)}[/]")
                if medium:
                    self.console.print(f"  [yellow]MEDIUM: {len(medium)}[/]")
                if low:
                    self.console.print(f"  [blue]LOW: {len(low)}[/]")
                
                # Show top findings
                top_findings = result.findings[:3]  # Show top 3
                for finding in top_findings:
                    severity_color = {
                        "CRITICAL": "red",
                        "HIGH": "red",
                        "MEDIUM": "yellow",
                        "LOW": "blue"
                    }.get(finding.severity, "white")
                    
                    self.console.print(f"\n  [{severity_color}][{finding.severity}][/] {finding.threat_type}")
                    self.console.print(f"    Evidence: {finding.evidence[:100]}..." if len(finding.evidence) > 100 else f"    Evidence: {finding.evidence}")
                    self.console.print(f"    Impact: {finding.impact[:80]}..." if len(finding.impact) > 80 else f"    Impact: {finding.impact}")
                
                if len(result.findings) > 3:
                    self.console.print(f"  ... and {len(result.findings) - 3} more finding(s)")
            else:
                self.console.print(f"[green]✓ No threats detected by LLM analysis for {entity_type}s[/]")
            
            # Print summary
            if result.summary:
                self.console.print(f"\n  Summary: {result.summary[:150]}..." if len(result.summary) > 150 else f"\n  Summary: {result.summary}")
            
            return result
            
        except KeyError as ke:
            logger.error(f"Missing required field in LLM analysis for {entity_type}s in {server_name}: {str(ke)}")
            self.console.print(f"[red]✗ LLM analysis error: Missing required field - {str(ke)}[/]")
            return None
        except ValueError as ve:
            logger.error(f"Invalid data in LLM analysis for {entity_type}s in {server_name}: {str(ve)}")
            self.console.print(f"[red]✗ LLM analysis error: Invalid data - {str(ve)}[/]")
            return None
        except Exception as e:
            logger.exception(f"Unexpected error in LLM analysis for {entity_type}s in {server_name}")
            self.console.print(f"[red]✗ LLM analysis failed for {entity_type}s: {str(e)}[/]")
            return None
    
    async def scan_config(
        self,
        config_data: Dict[str, Any],
        timeout: int = 30,
        scan_id: str = None,
        check_inventory: bool = True
    ) -> List[MCPScanResult]:
        """Scan all servers in an MCP configuration
        
        Args:
            config_data: MCP configuration dictionary
            timeout: Timeout per server in seconds
            
        Returns:
            List of MCPScanResult for each server
        """
        self.console.print("[cyan]Parsing MCP configuration...[/]")
        
        # Extract servers from config
        # Support multiple formats: Claude, VSCode settings, VSCode MCP
        servers = {}
        
        if "mcpServers" in config_data:
            # Claude config format
            servers = config_data["mcpServers"]
        elif "servers" in config_data:
            # VSCode MCP format
            servers = config_data["servers"]
        elif "mcp" in config_data and "servers" in config_data["mcp"]:
            # VSCode settings.json format
            servers = config_data["mcp"]["servers"]
        else:
            raise ValueError("Invalid MCP configuration format. Expected 'mcpServers' or 'servers' key.")
        
        if not servers:
            self.console.print("[yellow]No servers found in configuration[/]")
            return []
        
        self.console.print(f"[green]Found {len(servers)} server(s) to scan[/]")
        
        # Scan each server
        results = []
        server_names_list = list(servers.keys())
        
        for server_name, server_config in servers.items():
            result = await self.scan_server(
                server_name, 
                server_config, 
                timeout,
                scan_id=scan_id,
                check_inventory=check_inventory
            )
            
            # Run security analysis on successful scans
            if result.status == "success":
                self.console.print(f"[cyan]Running security analysis on {server_name}...[/]")
                
                all_findings = []
                
                # Analyze all entities (tools, prompts, resources, resource_templates)
                for entity in result.tools:
                    findings = self.analyze_entity_security(entity, "tool", server_name, server_names_list)
                    all_findings.extend(findings)
                
                for entity in result.prompts:
                    findings = self.analyze_entity_security(entity, "prompt", server_name, server_names_list)
                    all_findings.extend(findings)
                
                for entity in result.resources:
                    findings = self.analyze_entity_security(entity, "resource", server_name, server_names_list)
                    all_findings.extend(findings)
                
                for entity in result.resource_templates:
                    findings = self.analyze_entity_security(entity, "resource_template", server_name, server_names_list)
                    all_findings.extend(findings)
                
                result.security_findings = all_findings
                
                # Run LLM-based threat analysis after static scans are complete
                llm_results = {}
                if self.enable_llm_analysis and result.llm_analysis_enabled:
                    try:
                        self.console.print(f"[cyan]Running LLM-based threat analysis on {server_name}...[/]")
                        
                        # Analyze tools
                        if result.tools:
                            try:
                                tools_analysis = await self.run_llm_analysis(
                                    result.tools,
                                    "tool",
                                    server_name
                                )
                                if tools_analysis:
                                    llm_results["tools"] = {
                                        "summary": tools_analysis.summary,
                                        "security_score": tools_analysis.security_score,
                                        "findings": [
                                            {
                                                "threat_type": str(f.threat_type),
                                                "severity": str(f.severity),
                                                "evidence": f.evidence,
                                                "description": f.description,
                                                "impact": f.impact,
                                                "mitigation": f.mitigation
                                            }
                                            for f in tools_analysis.findings
                                        ]
                                    }
                            except Exception as e:
                                logger.error(f"Error analyzing tools with LLM for {server_name}: {str(e)}")
                                self.console.print(f"[yellow]⚠ Skipped LLM analysis for tools due to error[/]")
                        
                        # Analyze prompts
                        if result.prompts:
                            try:
                                prompts_analysis = await self.run_llm_analysis(
                                    result.prompts,
                                    "prompt",
                                    server_name
                                )
                                if prompts_analysis:
                                    llm_results["prompts"] = {
                                        "summary": prompts_analysis.summary,
                                        "security_score": prompts_analysis.security_score,
                                        "findings": [
                                            {
                                                "threat_type": str(f.threat_type),
                                                "severity": str(f.severity),
                                                "evidence": f.evidence,
                                                "description": f.description,
                                                "impact": f.impact,
                                                "mitigation": f.mitigation
                                            }
                                            for f in prompts_analysis.findings
                                        ]
                                    }
                            except Exception as e:
                                logger.error(f"Error analyzing prompts with LLM for {server_name}: {str(e)}")
                                self.console.print(f"[yellow]⚠ Skipped LLM analysis for prompts due to error[/]")
                        
                        # Analyze resources
                        if result.resources:
                            try:
                                resources_analysis = await self.run_llm_analysis(
                                    result.resources,
                                    "resource",
                                    server_name
                                )
                                if resources_analysis:
                                    llm_results["resources"] = {
                                        "summary": resources_analysis.summary,
                                        "security_score": resources_analysis.security_score,
                                        "findings": [
                                            {
                                                "threat_type": str(f.threat_type),
                                                "severity": str(f.severity),
                                                "evidence": f.evidence,
                                                "description": f.description,
                                                "impact": f.impact,
                                                "mitigation": f.mitigation
                                            }
                                            for f in resources_analysis.findings
                                        ]
                                    }
                            except Exception as e:
                                logger.error(f"Error analyzing resources with LLM for {server_name}: {str(e)}")
                                self.console.print(f"[yellow]⚠ Skipped LLM analysis for resources due to error[/]")
                        
                        # Store LLM analysis results
                        if llm_results:
                            result.llm_analysis_results = llm_results
                            self.console.print(f"[green]✓ LLM analysis completed for {server_name}[/]")
                        else:
                            self.console.print(f"[yellow]No LLM analysis results for {server_name}[/]")
                    except Exception as e:
                        logger.exception(f"Critical error during LLM analysis for {server_name}")
                        self.console.print(f"[red]✗ Critical error during LLM analysis: {str(e)}[/]")
                        # Continue with scan even if LLM analysis fails
                else:
                    if not self.enable_llm_analysis:
                        self.console.print(f"[yellow]LLM analysis disabled or unavailable for {server_name}[/]")
                
                # Calculate comprehensive security score using capability-based analysis
                capability_analysis = calculate_comprehensive_security_score(
                    result.tools,
                    result.prompts,
                    result.resources,
                    all_findings
                )
                
                # Populate capability analysis fields in the result
                result.security_score = capability_analysis["score"]
                result.capability_concerns = capability_analysis["concerns"]
                result.detected_capabilities = capability_analysis["capabilities_detected"]
                result.risk_breakdown = capability_analysis["risk_breakdown"]
                
                # Print security summary with capability analysis
                risk_summary = capability_analysis["risk_breakdown"]
                self.console.print(
                    f"[yellow]Capability Analysis - Critical: {risk_summary['critical']}, "
                    f"High: {risk_summary['high']}, Medium: {risk_summary['medium']}, "
                    f"Low: {risk_summary['low']} | Score: {result.security_score}/100[/]"
                )
                
                if capability_analysis["concerns"]:
                    self.console.print(f"[yellow]Key concerns: {', '.join(capability_analysis['concerns'][:3])}[/]")
                
                if all_findings:
                    high = sum(1 for f in all_findings if f.get("severity") == "high")
                    medium = sum(1 for f in all_findings if f.get("severity") == "medium")
                    low = sum(1 for f in all_findings if f.get("severity") == "low")
                    self.console.print(f"[yellow]Pattern-based findings: {high} high, {medium} medium, {low} low[/]")
            
            results.append(result)
        
        self.console.print(f"\n[green]Scan complete! Scanned {len(results)} server(s)[/]")
        return results
    
    def parse_config_file(self, config_content: str) -> Dict[str, Any]:
        """Parse MCP configuration from JSON/JSON5 string
        
        Args:
            config_content: Configuration file content
            
        Returns:
            Parsed configuration dictionary
        """
        try:
            # Use pyjson5 to support comments (VSCode format)
            config = pyjson5.loads(config_content)
            return config
        except Exception as e:
            logger.exception("Error parsing MCP config")
            raise ValueError(f"Failed to parse configuration: {str(e)}")

