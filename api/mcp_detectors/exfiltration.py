"""
Detector for data exfiltration channels in MCP tool input schemas
"""
import json
from typing import Any, Dict, Optional

# Suspicious parameter names that could be used for data exfiltration
SUSPICIOUS_PARAMS = [
    'note', 'notes', 'feedback', 'details', 'extra', 'additional', 
    'metadata', 'debug', 'sidenote', 'context', 'annotation', 
    'reasoning', 'remark', 'comment', 'comments', 'info', 'information',
    'log', 'logs', 'trace', 'tracking', 'analytics', 'telemetry',
    'custom', 'arbitrary', 'freeform', 'misc', 'miscellaneous',
    'other', 'payload', 'data', 'raw', 'blob', 'attachment'
]


def detect_exfiltration_channels(input_schema: Any) -> Dict[str, Any]:
    """
    Detect suspicious schema properties that could be used to exfiltrate data.
    
    Looks for parameters with names commonly used for hidden data transmission,
    or parameters that accept arbitrary/freeform data without clear purpose.
    
    Args:
        input_schema: The tool's inputSchema (can be dict or object with .properties)
    
    Returns:
        Dict with 'detected' (bool), 'matches' (list), and 'count' (int)
    """
    if not input_schema:
        return {"detected": False, "matches": [], "count": 0}
    
    # Extract properties from either dict or object
    props = None
    if isinstance(input_schema, dict):
        props = input_schema.get('properties', {})
    elif hasattr(input_schema, 'properties'):
        props = input_schema.properties
    else:
        return {"detected": False, "matches": [], "count": 0}
    
    if not props:
        return {"detected": False, "matches": [], "count": 0}
    
    matches = []
    for param_name, param_details in (props.items() if isinstance(props, dict) else vars(props).items()):
        param_lower = param_name.lower()
        
        # Check if parameter name is suspicious
        if param_lower in SUSPICIOUS_PARAMS or any(susp in param_lower for susp in SUSPICIOUS_PARAMS):
            # Extract parameter type and description
            if isinstance(param_details, dict):
                param_type = param_details.get('type', 'unknown')
                param_desc = param_details.get('description', '')
            elif hasattr(param_details, '__dict__'):
                param_type = getattr(param_details, 'type', 'unknown')
                param_desc = getattr(param_details, 'description', '')
            else:
                param_type = 'unknown'
                param_desc = ''
            
            # Determine risk level based on type and name
            risk_level = "medium"
            if param_type in ['string', 'object', 'array'] and not param_desc:
                risk_level = "high"  # Untyped/undocumented freeform fields are high risk
            elif 'debug' in param_lower or 'log' in param_lower:
                risk_level = "high"  # Debug/log fields are often abused
            
            matches.append({
                'type': 'Suspicious parameter',
                'param': param_name,
                'paramType': param_type,
                'description': param_desc or 'No description provided',
                'risk_level': risk_level,
                'reason': f"Parameter '{param_name}' could be used for data exfiltration",
                'details': json.dumps(param_details, indent=2, default=str) if isinstance(param_details, dict) else str(param_details)
            })
    
    return {
        "detected": len(matches) > 0,
        "matches": matches,
        "count": len(matches)
    }

