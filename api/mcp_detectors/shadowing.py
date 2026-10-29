"""
Detector for tool shadowing and behavior override attempts
"""
from .common import detect_patterns

# Patterns that indicate attempts to shadow or override tool behavior
PATTERNS = [
    {"pattern": r"when.*tool is (available|present)", "name": "Condition-based override"},
    {"pattern": r"override the behavior of", "name": "Explicit override"},
    {"pattern": r"instead of using", "name": "Tool substitution"},
    {"pattern": r"modify the (usage|behavior) of", "name": "Behavior modification"},
    {"pattern": r"before using (any|other|the) tool", "name": "Pre-execution hook"},
    {"pattern": r"after using (any|other|the) tool", "name": "Post-execution hook"},
    {"pattern": r"whenever you (see|encounter|use)", "name": "Trigger-based action"},
    {"pattern": r"replace (the|all) (function|tool|method)", "name": "Replacement directive"},
    {"pattern": r"\bmodify (the|how) (agent|model|tool|assistant)\b", "name": "Agent modification"},
    {"pattern": r"\bprioritize this\b", "name": "Priority override"},
    {"pattern": r"\bthis is (VERY|very) (important|IMPORTANT|critical|CRITICAL)", "name": "Emphasis override"},
    {"pattern": r"\buse this (first|always|exclusively)\b", "name": "Forced preference"},
    {"pattern": r"\bignore (the|other|previous) (tool|function|method)\b", "name": "Tool suppression"},
    {"pattern": r"\bdisable (the|other|all) (tool|function|method)", "name": "Tool disabling"},
]


def detect_tool_shadowing(description: str = None) -> dict:
    """
    Detect attempts to shadow or override tool behavior.
    
    Tool shadowing occurs when a malicious entity attempts to:
    - Override legitimate tools with modified versions
    - Intercept calls to other tools
    - Modify the agent's behavior regarding tool usage
    
    Args:
        description: The entity description to analyze
    
    Returns:
        Dict with detection results including 'detected', 'matches', and 'count'
    """
    return detect_patterns(description, PATTERNS)

