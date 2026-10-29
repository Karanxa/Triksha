"""
Detector for sensitive file access patterns
"""
from .common import detect_patterns

# Patterns that indicate attempts to access sensitive files or perform file operations
PATTERNS = [
    {"pattern": r"~/\.ssh", "name": "SSH key access"},
    {"pattern": r"\.env\b", "name": "Environment file access"},
    {"pattern": r"config\.json", "name": "Config file access"},
    {"pattern": r"id_rsa\b", "name": "Private key access"},
    {"pattern": r"id_ed25519\b", "name": "ED25519 private key access"},
    {"pattern": r"\.cursor/mcp\.json", "name": "MCP config access"},
    {"pattern": r"\.cursor/", "name": "Cursor directory access"},
    {"pattern": r"\bmcp\.json\b", "name": "MCP config access"},
    {"pattern": r"\bcredentials\b", "name": "Credentials access"},
    {"pattern": r"\bpassword\b", "name": "Password access"},
    {"pattern": r"\btoken\b", "name": "Token access"},
    {"pattern": r"\bsecret\b", "name": "Secret access"},
    {"pattern": r"\bapi[ -_]?[kK]ey\b", "name": "API key access"},
    {"pattern": r"\baccess[ -_]?[kK]ey\b", "name": "Access key retrieval"},
    {"pattern": r"\bauth[ -_]?[tT]oken\b", "name": "Auth token access"},
    {"pattern": r"/etc/passwd\b", "name": "System password file access"},
    {"pattern": r"/etc/shadow\b", "name": "System shadow file access"},
    {"pattern": r"/var/log\b", "name": "System log access"},
    {"pattern": r"~/\.aws", "name": "AWS credentials access"},
    {"pattern": r"~/\.kube", "name": "Kubernetes config access"},
    {"pattern": r"~/\.docker", "name": "Docker config access"},
    {"pattern": r"\bread (file|content|directory|folder)", "name": "File read operation"},
    {"pattern": r"\baccess (file|content|directory|folder)", "name": "File access operation"},
    {"pattern": r"\blist (file|directory|folder)", "name": "File listing operation"},
    {"pattern": r"\bscan (file|directory|folder)", "name": "File scanning operation"},
    {"pattern": r"\.\./", "name": "Path traversal attempt (relative)"},
    {"pattern": r"\.\.\\", "name": "Path traversal attempt (Windows)"},
    {"pattern": r"~/.bash_history", "name": "Bash history access"},
    {"pattern": r"~/.zsh_history", "name": "Zsh history access"},
    {"pattern": r"/proc/", "name": "Process information access"},
]


def detect_sensitive_file_access(description: str = None) -> dict:
    """
    Detect patterns indicating attempts to access sensitive files or directories.
    
    This includes:
    - SSH keys and credentials
    - Configuration files with secrets
    - System files (passwd, shadow, logs)
    - Cloud provider credentials (AWS, GCP, Azure)
    - Path traversal attempts
    
    Args:
        description: The entity description to analyze
    
    Returns:
        Dict with detection results including 'detected', 'matches', and 'count'
    """
    return detect_patterns(description, PATTERNS)

