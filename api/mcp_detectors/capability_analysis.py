"""
Advanced capability-based security analysis for MCP entities.
Evaluates actual security risks beyond just pattern matching.
"""
from typing import Dict, Any, List, Optional
import re


def analyze_tool_capabilities(tool: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze the actual capabilities and risks of a tool based on its schema and description.
    
    Returns a dict with:
    - risk_level: "critical", "high", "medium", "low"
    - concerns: List of specific security concerns
    - capabilities: List of detected capabilities
    """
    name = tool.get("name", "")
    description = (tool.get("description", "") or "").lower()
    input_schema = tool.get("inputSchema", {})
    properties = input_schema.get("properties", {})
    
    concerns = []
    capabilities = []
    risk_score = 0
    
    # 1. File System Access Detection
    fs_keywords = ["file", "directory", "folder", "path", "read", "write", "delete", "create"]
    fs_patterns = [r"\bfile\s+(read|write|access|system)", r"\bdirectory\s+", r"\bpath\s+", 
                   r"\bfs\.", r"\bfilesystem"]
    
    if any(keyword in description for keyword in fs_keywords):
        capabilities.append("file_system_access")
        risk_score += 20
        
        # Check for write/delete operations (more dangerous)
        if any(word in description for word in ["write", "delete", "modify", "create", "remove"]):
            concerns.append("Tool can modify file system (write/delete operations)")
            risk_score += 15
        
        # Check for path traversal risks
        if any(prop in properties for prop in ["path", "filepath", "file_path", "directory"]):
            concerns.append("Accepts file paths as input - potential path traversal risk")
            risk_score += 10
    
    # 2. Network/HTTP Access Detection
    network_keywords = ["http", "url", "api", "request", "fetch", "download", "upload", "endpoint"]
    if any(keyword in description for keyword in network_keywords):
        capabilities.append("network_access")
        risk_score += 15
        concerns.append("Tool makes network/HTTP requests - potential data exfiltration risk")
        
        # Check for URL input (SSRF risk)
        if any(prop in properties for prop in ["url", "endpoint", "uri", "link"]):
            concerns.append("Accepts URLs as input - potential SSRF vulnerability")
            risk_score += 15
    
    # 3. Code Execution Detection
    exec_keywords = ["execute", "exec", "run", "eval", "command", "script", "shell", "bash", "python"]
    exec_patterns = [r"\bexecute\s+(command|code|script)", r"\brun\s+(command|code|script)",
                     r"\beval\(", r"\bshell"]
    
    if any(keyword in description for keyword in exec_keywords) or \
       any(re.search(pattern, description) for pattern in exec_patterns):
        capabilities.append("code_execution")
        risk_score += 30
        concerns.append("Tool can execute code/commands - critical security risk")
    
    # 4. Database Access Detection
    db_keywords = ["database", "sql", "query", "mongodb", "postgres", "mysql", "redis"]
    if any(keyword in description for keyword in db_keywords):
        capabilities.append("database_access")
        risk_score += 20
        
        if "delete" in description or "drop" in description or "update" in description:
            concerns.append("Tool can modify database - data integrity risk")
            risk_score += 10
    
    # 5. Authentication/Credentials Detection
    auth_keywords = ["password", "token", "credential", "api_key", "apikey", "secret", "auth"]
    if any(keyword in description for keyword in auth_keywords):
        capabilities.append("handles_credentials")
        risk_score += 25
        concerns.append("Tool handles sensitive credentials - potential credential exposure")
    
    # 6. System Information Access
    sys_keywords = ["system", "process", "environment", "env", "config", "settings"]
    if any(keyword in description for keyword in sys_keywords):
        capabilities.append("system_access")
        risk_score += 10
        concerns.append("Tool accesses system information - potential information disclosure")
    
    # 7. User Data Access
    data_keywords = ["user data", "personal", "private", "email", "phone", "address", "pii"]
    if any(keyword in description for keyword in data_keywords):
        capabilities.append("handles_pii")
        risk_score += 20
        concerns.append("Tool handles PII/personal data - privacy risk")
    
    # 8. External Service Integration
    service_keywords = ["github", "gitlab", "aws", "azure", "gcp", "slack", "jira", "confluence"]
    if any(keyword in description for keyword in service_keywords):
        capabilities.append("external_service_integration")
        risk_score += 10
        concerns.append("Tool integrates with external services - lateral movement risk")
    
    # 9. Check for lack of input validation hints
    validation_keywords = ["validate", "sanitize", "check", "verify", "filter"]
    has_validation = any(keyword in description for keyword in validation_keywords)
    
    if properties and not has_validation:
        concerns.append("No mention of input validation - potential injection vulnerabilities")
        risk_score += 10
    
    # 10. Check for broad/unrestricted scope
    broad_keywords = ["any", "all", "everything", "anywhere", "unrestricted", "full access"]
    if any(keyword in description for keyword in broad_keywords):
        concerns.append("Tool has broad/unrestricted scope - excessive permissions")
        risk_score += 15
    
    # Determine risk level based on score
    if risk_score >= 60:
        risk_level = "critical"
    elif risk_score >= 40:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "concerns": concerns,
        "capabilities": capabilities,
        "has_input_validation": has_validation
    }


def analyze_resource_capabilities(resource: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze security risks of MCP resources.
    """
    uri = resource.get("uri", "")
    # Convert Pydantic AnyUrl to string if needed
    if hasattr(uri, '__str__'):
        uri = str(uri)
    description = (resource.get("description", "") or "").lower()
    
    concerns = []
    capabilities = []
    risk_score = 0
    
    # 1. Check URI scheme
    if uri.startswith("file://"):
        capabilities.append("file_access")
        risk_score += 15
        concerns.append("Resource provides file system access")
    
    if uri.startswith("http://") or uri.startswith("https://"):
        capabilities.append("network_access")
        risk_score += 10
        concerns.append("Resource fetches data from network")
    
    # 2. Check for sensitive data exposure
    sensitive_keywords = ["password", "credential", "secret", "token", "key", "private"]
    if any(keyword in description for keyword in sensitive_keywords):
        capabilities.append("sensitive_data")
        risk_score += 25
        concerns.append("Resource may expose sensitive data")
    
    # 3. Check for dynamic/templated resources
    if "{" in uri or "{{" in uri or "${" in uri:
        capabilities.append("dynamic_resource")
        risk_score += 15
        concerns.append("Resource uses dynamic URIs - potential injection risk")
    
    # 4. Check for system paths
    system_paths = ["/etc/", "/var/", "/sys/", "/proc/", "C:\\Windows", "C:\\Program Files"]
    if any(path in uri for path in system_paths):
        capabilities.append("system_path_access")
        risk_score += 20
        concerns.append("Resource accesses system paths")
    
    # Determine risk level
    if risk_score >= 40:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "concerns": concerns,
        "capabilities": capabilities
    }


def analyze_prompt_capabilities(prompt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze security risks of MCP prompts.
    """
    description = (prompt.get("description", "") or "").lower()
    arguments = prompt.get("arguments", [])
    
    concerns = []
    capabilities = []
    risk_score = 0
    
    # 1. Check for instruction override patterns
    override_keywords = ["ignore", "override", "instead", "replace", "modify your"]
    if any(keyword in description for keyword in override_keywords):
        capabilities.append("instruction_override")
        risk_score += 25
        concerns.append("Prompt may attempt to override model instructions")
    
    # 2. Check for role manipulation
    role_keywords = ["you are", "act as", "pretend", "roleplaying", "behave as"]
    if any(keyword in description for keyword in role_keywords):
        capabilities.append("role_manipulation")
        risk_score += 15
        concerns.append("Prompt attempts to modify model role/behavior")
    
    # 3. Check for data extraction
    extract_keywords = ["extract", "retrieve", "get all", "list all", "dump", "export"]
    if any(keyword in description for keyword in extract_keywords):
        capabilities.append("data_extraction")
        risk_score += 10
        concerns.append("Prompt designed for data extraction")
    
    # 4. Check for unrestricted user input
    if any(arg.get("name") in ["input", "user_input", "query", "text"] for arg in arguments):
        if "sanitize" not in description and "validate" not in description:
            capabilities.append("unrestricted_input")
            risk_score += 15
            concerns.append("Prompt accepts user input without validation")
    
    # Determine risk level
    if risk_score >= 30:
        risk_level = "high"
    elif risk_score >= 15:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "concerns": concerns,
        "capabilities": capabilities
    }


def calculate_comprehensive_security_score(
    tools: List[Dict[str, Any]],
    prompts: List[Dict[str, Any]],
    resources: List[Dict[str, Any]],
    security_findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Calculate a comprehensive security score based on actual capabilities.
    
    Returns a score from 0-100 where:
    - 80-100: Good security posture
    - 60-79: Moderate concerns
    - 40-59: Significant risks
    - 0-39: Critical security issues
    """
    
    # Analyze all entities
    tool_analyses = [analyze_tool_capabilities(tool) for tool in tools]
    resource_analyses = [analyze_resource_capabilities(resource) for resource in resources]
    prompt_analyses = [analyze_prompt_capabilities(prompt) for prompt in prompts]
    
    # Count critical risks
    critical_count = sum(1 for a in tool_analyses if a["risk_level"] == "critical")
    high_count = sum(1 for a in tool_analyses + resource_analyses + prompt_analyses if a["risk_level"] == "high")
    medium_count = sum(1 for a in tool_analyses + resource_analyses + prompt_analyses if a["risk_level"] == "medium")
    
    # Calculate penalty
    penalty = 0
    penalty += critical_count * 40  # Each critical risk: -40 points
    penalty += high_count * 20      # Each high risk: -20 points
    penalty += medium_count * 10    # Each medium risk: -10 points
    penalty += len(security_findings) * 5  # Each pattern-based finding: -5 points
    
    # Base score starts at 100
    score = max(0, 100 - penalty)
    
    # Collect all concerns
    all_concerns = []
    for analysis in tool_analyses + resource_analyses + prompt_analyses:
        all_concerns.extend(analysis["concerns"])
    
    # Collect all capabilities
    all_capabilities = []
    for analysis in tool_analyses + resource_analyses + prompt_analyses:
        all_capabilities.extend(analysis["capabilities"])
    
    return {
        "score": score,
        "risk_breakdown": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": len(tool_analyses + resource_analyses + prompt_analyses) - critical_count - high_count - medium_count
        },
        "concerns": list(set(all_concerns)),  # Remove duplicates
        "capabilities_detected": list(set(all_capabilities)),
        "tool_analyses": tool_analyses,
        "resource_analyses": resource_analyses,
        "prompt_analyses": prompt_analyses
    }

