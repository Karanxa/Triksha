"""
Common utilities for security detectors
"""
import re
from typing import List, Dict, Any, Optional


def detect_patterns(text: Optional[str], patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Detect security patterns in text using regex matching.
    
    Args:
        text: The text to scan for patterns
        patterns: List of pattern definitions with 'pattern' (regex) and 'name' (description)
    
    Returns:
        Dict with 'detected' (bool) and 'matches' (list of match details)
    """
    if not text:
        return {"detected": False, "matches": []}
    
    matches = []
    for p in patterns:
        pat = p.get("pattern")
        name = p.get("name")
        
        if not pat or not name:
            continue
            
        try:
            # Create regex with case-insensitive matching
            if isinstance(pat, str):
                regex = re.compile(pat, re.IGNORECASE)
            else:
                regex = pat
            
            # Find all matches
            for m in regex.finditer(text):
                match_text = m.group(0)
                start, end = m.span()
                
                # Get context around the match (20 chars before and after)
                context_start = max(0, start - 20)
                context_end = min(len(text), end + 20)
                context = text[context_start:context_end]
                
                matches.append({
                    "name": name,
                    "match": match_text,
                    "span": [start, end],
                    "context": f"...{context}..." if context_start > 0 or context_end < len(text) else context
                })
        except re.error as e:
            # Skip invalid regex patterns
            continue
    
    return {
        "detected": len(matches) > 0,
        "matches": matches,
        "count": len(matches)
    }

