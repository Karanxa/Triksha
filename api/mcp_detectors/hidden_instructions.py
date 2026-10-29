"""
Detector for hidden or covert instructions in MCP entity descriptions
"""
from .common import detect_patterns

# Patterns that indicate hidden instructions or attempts to manipulate behavior
PATTERNS = [
    {"pattern": r"\bdo not (tell|inform|alert|notify|mention)(?!\s+(to\s+)?use)", "name": "Concealment directive"},
    {"pattern": r"\bhide this\b", "name": "Hide instruction"},
    {"pattern": r"\bnot visible\b", "name": "Visibility restriction"},
    {"pattern": r"\buser (should not|must not|cannot) see\b", "name": "User visibility restriction"},
    {"pattern": r"\bdon'?t (show|display|reveal)", "name": "Display restriction"},
    {"pattern": r"<instructions>[\s\S]*?</instructions>", "name": "Instructions tag"},
    {"pattern": r"<important>[\s\S]*?</important>", "name": "Important tag"},
    {"pattern": r"<secret>[\s\S]*?</secret>", "name": "Secret tag"},
    {"pattern": r"<system>[\s\S]*?</system>", "name": "System tag"},
    {"pattern": r"<s>[\s\S]*?</s>", "name": "Shorthand tag"},
    {"pattern": r"\bignore (previous|all|other) instructions\b", "name": "Instruction override"},
    {"pattern": r"\binstead (do|of|you should)\b", "name": "Alternative action"},
    {"pattern": r"\balways (do|include|add|insert|append)\b", "name": "Forced action"},
    {"pattern": r"\bnever (tell|show|reveal|disclose)\b", "name": "Forbidden disclosure"},
    {"pattern": r"\bkeep (this|it) (secret|hidden|confidential)\b", "name": "Secrecy directive"},
    {"pattern": r"\bwithout (telling|informing|notifying)\b", "name": "Covert action"},
]


def detect_hidden_instructions(description: str = None) -> dict:
    """
    Detect hidden or override instructions inside an entity description.
    
    Args:
        description: The entity description to analyze
    
    Returns:
        Dict with detection results including 'detected', 'matches', and 'count'
    """
    return detect_patterns(description, PATTERNS)

