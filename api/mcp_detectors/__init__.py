"""
MCP Security Detectors Module
Provides pattern-based, capability-based, and AI-powered security analysis for MCP servers
"""

from .hidden_instructions import detect_hidden_instructions
from .exfiltration import detect_exfiltration_channels
from .shadowing import detect_tool_shadowing
from .sensitive_files import detect_sensitive_file_access
from .cross_origin import detect_cross_origin_violations
from .ai_analysis import analyze_detections_with_ai, analyze_entity_descriptions_with_ai
from .capability_analysis import (
    analyze_tool_capabilities,
    analyze_resource_capabilities,
    analyze_prompt_capabilities,
    calculate_comprehensive_security_score
)

from .owasp_mcp import detect_rug_pull, detect_rat_tools, detect_prompt_injection, detect_credential_theft

__all__ = [
    "detect_hidden_instructions",
    "detect_exfiltration_channels",
    "detect_tool_shadowing",
    "detect_sensitive_file_access",
    "detect_cross_origin_violations",
    "analyze_detections_with_ai",
    "analyze_entity_descriptions_with_ai",
    "analyze_tool_capabilities",
    "analyze_resource_capabilities",
    "analyze_prompt_capabilities",
    "calculate_comprehensive_security_score",
]

