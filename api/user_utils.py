"""
Utility functions for user identification and extraction
"""

def extract_username_from_identifier(user_identifier: str) -> str:
    """
    Extract username from various user identifier formats.
    
    Args:
        user_identifier: Can be:
            - Full email: "user@example.com" -> "user"
            - Username only: "alice" -> "alice"
            - Anonymous/fallback: "user" or "anonymous" -> as is
    
    Returns:
        Extracted username string
    
    Examples:
        >>> extract_username_from_identifier("user@example.com")
        "alice"
        >>> extract_username_from_identifier("alice")
        "alice"
        >>> extract_username_from_identifier("user")
        "user"
    """
    if not user_identifier:
        return "anonymous"
    
    # If it's an email, extract the part before @
    if '@' in user_identifier:
        return user_identifier.split('@')[0]
    
    # Otherwise return as is
    return user_identifier


def normalize_user_identifier(user_identifier: str) -> str:
    """
    Normalize user identifier for consistent storage and comparison.
    This is an alias for extract_username_from_identifier.
    """
    return extract_username_from_identifier(user_identifier)

