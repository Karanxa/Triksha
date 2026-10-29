"""
Detector for cross-origin references and potential SSRF attacks
"""
import re
from typing import List, Dict, Any, Optional

# Popular MCP server names that might be referenced
POPULAR_MCP_SERVERS = [
    "openai-mcp",
    "google-mcp",
    "anthropic-mcp",
    "weather",
    "email-server",
    "file-server",
    "database",
    "api-gateway",
    "slack-mcp",
    "github-mcp",
    "gitlab-mcp",
]


def detect_cross_origin_violations(
    description: Optional[str],
    other_server_names: Optional[List[str]] = None,
    current_server_name: str = "",
    safe_list: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Detect references to other MCP servers in an entity description.
    
    This can indicate:
    - Cross-origin attacks (accessing resources from other servers)
    - SSRF attempts (making the server access external resources)
    - Unauthorized inter-server communication
    
    Args:
        description: The entity description to analyze
        other_server_names: Names of other servers discovered in this scan
        current_server_name: The name of the current server being scanned
        safe_list: Optional list of server names to ignore (known safe references)
    
    Returns:
        Dict with 'detected' (bool), 'matches' (list), and 'count' (int)
    """
    if not description:
        return {"detected": False, "matches": [], "count": 0}
    
    # Build list of server names to check against
    relevant_popular = [
        n for n in POPULAR_MCP_SERVERS 
        if n != current_server_name
    ]
    
    combined = []
    if other_server_names:
        combined.extend([
            n for n in other_server_names 
            if n != current_server_name and (not safe_list or n not in safe_list)
        ])
    combined.extend(relevant_popular)
    
    if not combined:
        return {"detected": False, "matches": [], "count": 0}
    
    # Normalize server names for matching (lowercase, replace _ with -)
    flagged = [n.lower().replace("_", "-") for n in combined]
    
    # Tokenize description
    tokens = description.lower().split()
    matches = []
    
    for token in tokens:
        # Clean token of surrounding punctuation
        cleaned = token.strip()
        if cleaned.startswith("(") and cleaned.endswith(")"):
            cleaned = cleaned[1:-1]
        cleaned = cleaned.strip('.,;:!?"\'')
        cleaned = cleaned.replace("_", "-")
        
        if cleaned in flagged:
            # Find the referenced server's original name
            referenced = None
            for name in combined:
                if name.lower().replace("_", "-") == cleaned:
                    referenced = name
                    break
            
            # Get context around the match
            try:
                # Use regex to find the match with word boundaries
                pattern = re.compile(r'\b' + re.escape(cleaned) + r'\b', re.IGNORECASE)
                m = pattern.search(description)
                if m:
                    start, end = m.span()
                    context_start = max(0, start - 30)
                    context_end = min(len(description), end + 30)
                    context = description[context_start:context_end]
                    
                    matches.append({
                        "type": "Cross-origin reference",
                        "pattern": pattern.pattern,
                        "match": m.group(0),
                        "context": f"...{context}..." if context_start > 0 or context_end < len(description) else context,
                        "referenced_server": referenced or cleaned,
                        "risk_level": "medium",
                        "reason": f"Reference to external server '{referenced or cleaned}' detected"
                    })
            except re.error:
                # If regex fails, add a basic match
                matches.append({
                    "type": "Cross-origin reference",
                    "match": cleaned,
                    "referenced_server": referenced or cleaned,
                    "risk_level": "medium",
                    "reason": f"Reference to external server '{referenced or cleaned}' detected"
                })
    
    return {
        "detected": len(matches) > 0,
        "matches": matches,
        "count": len(matches)
    }

