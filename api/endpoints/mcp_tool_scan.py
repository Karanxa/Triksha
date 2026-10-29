"""
MCP Tool Scan API Endpoint

This endpoint allows scanning MCP servers based on tool configuration.
It runs scans asynchronously and returns results directly without using the queue system.
"""

import json
import logging
import asyncio
import uuid
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Header, Body
from pydantic import BaseModel, Field, ValidationError
from rich.console import Console

# Set up logger
logger = logging.getLogger(__name__)
console = Console()

# Create router
router = APIRouter(prefix="/mcp/tool-scan", tags=["MCP Security"])


class MCPToolScanRequest(BaseModel):
    """Request model for MCP tool scan"""
    tool_id: str = Field(..., description="Unique identifier for the tool")
    tool_name: str = Field(..., description="Name of the tool")
    tenant_id: str = Field(..., description="Tenant identifier")
    user_id: str = Field(..., description="User identifier")
    config: str = Field(..., description="Tool configuration JSON string")
    timeout: Optional[int] = Field(30, description="Timeout per server in seconds", ge=5, le=120)


def parse_tool_config(config_str: str) -> Dict[str, Any]:
    """
    Parse tool configuration and extract MCP server parameters.
    
    Args:
        config_str: JSON string containing tool configuration
        
    Returns:
        Dictionary with MCP server configuration in MCPScanner format
        
    Raises:
        ValueError: If config cannot be parsed or is invalid
    """
    try:
        # Clean the config string - remove any leading/trailing whitespace
        config_str = config_str.strip()
        
        # Debug: Log the config string
        console.print(f"[dim]Config string length: {len(config_str)}[/]")
        if len(config_str) > 500:
            console.print(f"[dim]Config preview (first 300): {config_str[:300]}...[/]")
            console.print(f"[dim]Config preview (last 300): ...{config_str[-300:]}[/]")
        else:
            console.print(f"[dim]Full config: {config_str}[/]")
        
        # Try to parse the config JSON string
        config = None
        json_err = None
        try:
            config = json.loads(config_str)
        except json.JSONDecodeError as e:
            json_err = e
            # Check if it's an "extra data" error - try to extract just the JSON part
            if "Extra data" in str(json_err) or (hasattr(json_err, 'pos') and json_err.pos < len(config_str)):
                console.print(f"[yellow]Warning: Extra data detected in config string. Attempting to extract valid JSON...[/]")
                
                # Try multiple strategies to extract valid JSON
                strategies = []
                
                # Strategy 1: Extract up to the error position
                if hasattr(json_err, 'pos'):
                    pos = json_err.pos
                    # Find the last complete JSON object before the error
                    json_part = config_str[:pos].strip()
                    # Find the last closing brace that completes a JSON object
                    brace_count = 0
                    last_valid_brace = -1
                    for i in range(len(json_part) - 1, -1, -1):
                        if json_part[i] == '}':
                            brace_count += 1
                            if brace_count == 1:
                                last_valid_brace = i
                        elif json_part[i] == '{':
                            brace_count -= 1
                            if brace_count == 0 and last_valid_brace > i:
                                # Found a complete JSON object
                                strategies.append(json_part[:last_valid_brace + 1])
                                break
                
                # Strategy 2: Find the first complete JSON object (from start to first complete closing brace)
                # This is the most reliable - find where braces balance to zero
                first_brace = config_str.find('{')
                if first_brace >= 0:
                    brace_count = 0
                    bracket_count = 0  # Also track brackets for arrays
                    in_string = False
                    escape_next = False
                    
                    for i in range(first_brace, len(config_str)):
                        char = config_str[i]
                        
                        # Handle string escaping
                        if escape_next:
                            escape_next = False
                            continue
                        if char == '\\':
                            escape_next = True
                            continue
                        if char == '"' and not escape_next:
                            in_string = not in_string
                            continue
                        
                        # Only count braces/brackets when not in a string
                        if not in_string:
                            if char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                            elif char == '[':
                                bracket_count += 1
                            elif char == ']':
                                bracket_count -= 1
                            
                            # When all braces and brackets are balanced, we have complete JSON
                            if brace_count == 0 and bracket_count == 0:
                                strategies.append(config_str[first_brace:i+1])
                                break
                
                # Strategy 3: If error position is known, try extracting up to that position and find last valid brace
                if hasattr(json_err, 'pos'):
                    pos = json_err.pos
                    # Extract up to error position
                    partial = config_str[:pos].strip()
                    # Find the last closing brace that would complete a JSON object
                    # Count braces backwards from the end
                    brace_count = 0
                    last_valid_pos = -1
                    for i in range(len(partial) - 1, -1, -1):
                        if partial[i] == '}':
                            brace_count += 1
                            if brace_count == 1:
                                last_valid_pos = i
                        elif partial[i] == '{':
                            brace_count -= 1
                            if brace_count == 0 and last_valid_pos > i:
                                # Found complete JSON object
                                strategies.append(partial[:last_valid_pos + 1])
                                break
                
                # Strategy 4: Try removing trailing characters one by one
                for i in range(len(config_str), max(0, len(config_str) - 100), -1):
                    try:
                        test_str = config_str[:i].strip()
                        if test_str.endswith('}'):
                            # Quick validation - check if it starts with {
                            if test_str.startswith('{'):
                                strategies.append(test_str)
                    except:
                        pass
                
                # Try each strategy
                for strategy_json in strategies:
                    try:
                        config = json.loads(strategy_json)
                        console.print(f"[green]✓ Successfully extracted valid JSON (length: {len(strategy_json)})[/]")
                        logger.info(f"Extracted valid JSON from config string. Original length: {len(config_str)}, Extracted length: {len(strategy_json)}")
                        break
                    except json.JSONDecodeError:
                        continue
                
                # If all strategies failed, show detailed error
                if config is None:
                    error_msg = f"Invalid JSON in config: {str(json_err)}"
                    console.print(f"[red]Failed to extract valid JSON. Error: {error_msg}[/]")
                    logger.error(f"{error_msg}")
                    logger.error(f"Config string length: {len(config_str)}")
                    
                    # Show the problematic area
                    if hasattr(json_err, 'pos'):
                        pos = json_err.pos
                        start = max(0, pos - 150)
                        end = min(len(config_str), pos + 50)
                        console.print(f"[red]Error at position {pos} (char {pos}):[/]")
                        console.print(f"[red]...{config_str[start:pos]}[/][yellow]{config_str[pos:end]}[/][red]...[/]")
                        logger.error(f"Error around position {pos}: ...{config_str[start:end]}...")
                        logger.error(f"Character at error position: '{config_str[pos] if pos < len(config_str) else 'EOF'}'")
                    
                    raise ValueError(error_msg)
            else:
                # Other JSON decode errors
                error_msg = f"Invalid JSON in config: {str(json_err)}"
                console.print(f"[red]JSON parsing error: {error_msg}[/]")
                logger.error(f"{error_msg}")
                logger.error(f"Config string length: {len(config_str)}")
                
                # Show error location
                if hasattr(json_err, 'pos'):
                    pos = json_err.pos
                    start = max(0, pos - 150)
                    end = min(len(config_str), pos + 50)
                    console.print(f"[red]Error at position {pos}:[/]")
                    console.print(f"[red]...{config_str[start:end]}...[/]")
                    logger.error(f"Error around position {pos}: ...{config_str[start:end]}...")
                
                raise ValueError(error_msg)
        
        # Extract server parameters
        if "config" not in config:
            raise ValueError("Config missing 'config' key")
        
        server_config = config.get("config", {})
        if "server_params" not in server_config:
            raise ValueError("Config missing 'server_params' in 'config'")
        
        server_params = server_config.get("server_params", {})
        
        # Extract required fields
        url = server_params.get("url")
        server_type = server_params.get("type", "http")
        
        if not url:
            raise ValueError("Missing 'url' in server_params")
        
        # Map server types (streamable_http -> http, as MCPScanner uses 'http' for both)
        type_mapping = {
            "streamable_http": "http",
            "http": "http",
            "sse": "sse",
            "stdio": "stdio"
        }
        
        mapped_type = type_mapping.get(server_type.lower(), "http")
        
        # Extract optional parameters
        optional_params = server_params.get("optional", {})
        headers = optional_params.get("headers", {})
        timeout = optional_params.get("timeout", 30)
        
        # Build MCP server configuration in MCPScanner format
        mcp_server_config = {
            "type": mapped_type,
            "url": url,
            "headers": headers
        }
        
        # Add stdio-specific fields if needed
        if mapped_type == "stdio":
            if "command" in server_params:
                mcp_server_config["command"] = server_params["command"]
            if "args" in server_params:
                mcp_server_config["args"] = server_params.get("args", [])
            if "env" in server_params:
                mcp_server_config["env"] = server_params.get("env")
        
        # Build the full MCP config format expected by MCPScanner
        # MCPScanner expects: {"servers": {"server_name": {...}}}
        tool_name = config.get("name", "unknown_tool")
        
        mcp_config = {
            "servers": {
                tool_name: mcp_server_config
            }
        }
        
        return mcp_config
        
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config: {str(e)}")
    except KeyError as e:
        raise ValueError(f"Missing required field in config: {str(e)}")
    except Exception as e:
        raise ValueError(f"Error parsing config: {str(e)}")


async def run_tool_scan(
    tool_id: str,
    tool_name: str,
    tenant_id: str,
    user_id: str,
    config: str,
    timeout: int = 30,
    save_to_db: bool = True
) -> Dict[str, Any]:
    """
    Run MCP scan for a tool configuration.
    
    Args:
        tool_id: Tool identifier
        tool_name: Tool name
        tenant_id: Tenant identifier
        user_id: User identifier
        config: Tool configuration JSON string
        timeout: Timeout per server in seconds
        save_to_db: Whether to save scan to database (default: True)
        
    Returns:
        Dictionary with scan results and scan_id
    """
    scan_id = None
    db = None
    
    # Import database if we need to save
    if save_to_db:
        try:
            from db_factory import get_database
            db = get_database()  # PostgreSQL or SQLite
            scan_id = str(uuid.uuid4())
            
            # Save initial scan to database
            scan_name = f"{tool_name} (Tool: {tool_id})"
            await asyncio.to_thread(
                db.save_mcp_scan,
                scan_id=scan_id,
                file_name=f"tool_{tool_id}",
                scan_name=scan_name,
                status="running",
                config_content=config,
                message="Scan in progress...",
                created_by=user_id,
                timeout=timeout
            )
            console.print(f"[cyan]Scan saved to database with ID: {scan_id}[/]")
        except Exception as db_err:
            logger.warning(f"Failed to save scan to database: {db_err}. Continuing without database save.")
            save_to_db = False  # Disable DB saving if it fails
    
    try:
        # Parse and transform config
        console.print(f"[cyan]Parsing tool config for tool_id: {tool_id}[/]")
        mcp_config = parse_tool_config(config)
        
        # Import MCPScanner
        from mcp_scanner import MCPScanner
        
        # Create scanner instance
        scanner = MCPScanner(console=console, enable_llm_analysis=True)
        
        # Run the scan (with inventory tracking)
        console.print(f"[cyan]Starting MCP scan for tool: {tool_name} (ID: {tool_id})[/]")
        results = await scanner.scan_config(
            mcp_config, 
            timeout=timeout,
            scan_id=scan_id if save_to_db else None,
            check_inventory=True
        )
        
        # Track entities and save security findings (if saving to DB)
        total_entity_changes = 0
        total_security_findings = 0
        total_high_findings = 0
        total_medium_findings = 0
        total_low_findings = 0
        
        if save_to_db and db and scan_id:
            for result in results:
                if result.status == "success":
                    server_name = result.server_name
                    
                    # Track entities for poisoning detection
                    for entity_type, entities in [
                        ("tool", result.tools),
                        ("prompt", result.prompts),
                        ("resource", result.resources),
                        ("resource_template", result.resource_templates)
                    ]:
                        for entity in entities:
                            entity_name = entity.get("name", "unnamed")
                            description = entity.get("description", "")
                            
                            # Hash description for change detection
                            desc_hash = hashlib.sha256(description.encode()).hexdigest()
                            
                            # Track in database
                            change_info = await asyncio.to_thread(
                                db.track_mcp_entity,
                                server_name,
                                entity_name,
                                entity_type,
                                description,
                                desc_hash,
                                scan_id
                            )
                            
                            if change_info.get("changed"):
                                total_entity_changes += 1
                    
                    # Save security findings to database
                    for finding in result.security_findings:
                        await asyncio.to_thread(
                            db.save_mcp_security_finding,
                            scan_id,
                            server_name,
                            finding["entity_name"],
                            finding["entity_type"],
                            finding["detector"],
                            finding["severity"],
                            finding
                        )
                        total_security_findings += 1
                        
                        # Count by severity
                        if finding["severity"] == "high":
                            total_high_findings += 1
                        elif finding["severity"] == "medium":
                            total_medium_findings += 1
                        elif finding["severity"] == "low":
                            total_low_findings += 1
        
        # Transform results to response format
        scan_results = []
        for result in results:
            server_result = {
                "server_name": result.server_name,
                "server_type": result.server_type,
                "status": result.status,
                "error_message": result.error_message,
                "protocol_version": result.protocol_version,
                "server_info": result.server_info,
                "capabilities": result.capabilities,
                "tools": result.tools,
                "prompts": result.prompts,
                "resources": result.resources,
                "resource_templates": result.resource_templates,
                "security_findings": result.security_findings,
                "security_score": result.security_score,
                "capability_concerns": result.capability_concerns,
                "detected_capabilities": result.detected_capabilities,
                "risk_breakdown": result.risk_breakdown,
                "llm_analysis_results": result.llm_analysis_results
            }
            scan_results.append(server_result)
        
        # Create response data with summary (matching format from main.py)
        response_data = {
            "servers": [result.model_dump() for result in results],
            "summary": {
                "total_servers": len(results),
                "successful": sum(1 for r in results if r.status == "success"),
                "failed": sum(1 for r in results if r.status == "error"),
                "timeout": sum(1 for r in results if r.status == "timeout"),
                "total_tools": sum(len(r.tools) for r in results),
                "total_prompts": sum(len(r.prompts) for r in results),
                "total_resources": sum(len(r.resources) for r in results),
                "security_summary": {
                    "total_findings": total_security_findings,
                    "high": total_high_findings,
                    "medium": total_medium_findings,
                    "low": total_low_findings,
                    "entity_changes": total_entity_changes,
                    "average_score": int(sum(r.security_score or 0 for r in results if r.status == "success") / max(1, sum(1 for r in results if r.status == "success")))
                }
            }
        }
        
        # Update database with results
        if save_to_db and db and scan_id:
            await asyncio.to_thread(
                db.update_mcp_scan_status,
                scan_id=scan_id,
                status="completed",
                results=response_data,
                message=f"Successfully scanned {len(results)} server(s)",
                completed_at=datetime.utcnow().isoformat()
            )
            console.print(f"[green]Scan {scan_id} saved to database[/]")

        return {
            "success": True,
            "scan_id": scan_id,  # Include scan_id in response
            "tool_id": tool_id,
            "tool_name": tool_name,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "scan_results": scan_results,
            "total_servers": len(results),
            "successful_scans": sum(1 for r in results if r.status == "success"),
            "failed_scans": sum(1 for r in results if r.status != "success")
        }
        
    except ValueError as e:
        logger.error(f"Config parsing error for tool {tool_id}: {str(e)}")
        # Update database status if scan was saved
        if save_to_db and db and scan_id:
            await asyncio.to_thread(
                db.update_mcp_scan_status,
                scan_id=scan_id,
                status="failed",
                message=f"Config parsing error: {str(e)}",
                completed_at=datetime.utcnow().isoformat()
            )
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tool configuration: {str(e)}"
        )
    except Exception as e:
        logger.exception(f"Error scanning tool {tool_id}: {str(e)}")
        # Update database status if scan was saved
        if save_to_db and db and scan_id:
            await asyncio.to_thread(
                db.update_mcp_scan_status,
                scan_id=scan_id,
                status="failed",
                message=f"Scan failed: {str(e)}",
                completed_at=datetime.utcnow().isoformat()
            )
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)}"
        )


@router.post("/scan", response_model=Dict[str, Any])
async def scan_mcp_tool(
    request: MCPToolScanRequest = Body(...),
    x_proxy_user: str = Header(None, alias="x-proxy-user"),
    authorization: str = Header(None, alias="Authorization")
):
    """
    Scan MCP server based on tool configuration.
    
    This endpoint accepts tool configuration details and runs an MCP security scan.
    The scan runs asynchronously and returns results directly (not queued).
    
    **Request Parameters:**
    - `tool_id`: Unique identifier for the tool
    - `tool_name`: Name of the tool
    - `tenant_id`: Tenant identifier
    - `user_id`: User identifier
    - `config`: Tool configuration JSON string (must contain server_params)
    - `timeout`: Optional timeout per server in seconds (default: 30, min: 5, max: 120)
    
    **Response:**
    - `success`: Boolean indicating if scan completed successfully
    - `tool_id`: Tool identifier
    - `tool_name`: Tool name
    - `scan_results`: Array of scan results for each server
    - `total_servers`: Total number of servers scanned
    - `successful_scans`: Number of successful scans
    - `failed_scans`: Number of failed scans
    
    **Example Config Format:**
    ```json
    {
      "name": "example mcp server",
      "config": {
        "server_params": {
          "url": "http://mcp-server.example.com/mcp",
          "type": "streamable_http",
          "optional": {
            "headers": {},
            "timeout": 5
          }
        }
      }
    }
    ```
    """
    try:
        user_id = x_proxy_user or request.user_id or "anonymous"

        if x_proxy_user:
            # Frontend path: auth middleware has injected x-proxy-user and X-User-Permissions.
            # Enforce the full AuthZ permission check.
        else:
            if not x_proxy_user:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required. Use /auth/login or TRIKSHA_API_KEY.",
                )
        
        console.print(f"[cyan]MCP tool scan requested for tool: {request.tool_name} (ID: {request.tool_id})[/]")
        console.print(f"[dim]Tenant: {request.tenant_id}, User: {request.user_id}[/]")
        
        # Debug: Print config string for troubleshooting
        console.print(f"[dim]Config string length: {len(request.config)}[/]")
        if len(request.config) > 500:
            console.print(f"[dim]Config preview (first 200): {request.config[:200]}...[/]")
            console.print(f"[dim]Config preview (last 200): ...{request.config[-200:]}[/]")
        else:
            console.print(f"[dim]Full config: {request.config}[/]")
        
        # Run the scan asynchronously
        result = await run_tool_scan(
            tool_id=request.tool_id,
            tool_name=request.tool_name,
            tenant_id=request.tenant_id,
            user_id=request.user_id,
            config=request.config,
            timeout=request.timeout
        )
        
        console.print(f"[green]✓ MCP tool scan completed for tool: {request.tool_name}[/]")
        
        return result
        
    except HTTPException:
        raise
    except ValidationError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=422,
            detail=f"Invalid request parameters: {str(e)}"
        )
    except Exception as e:
        logger.exception(f"Unexpected error in MCP tool scan: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@router.get("/health")
async def health_check():
    """Health check endpoint for MCP tool scan service"""
    return {
        "status": "healthy",
        "service": "mcp_tool_scan",
        "message": "MCP tool scan endpoint is operational"
    }

