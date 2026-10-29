"""
Environment loader for the API - standalone version.
"""

import os
from pathlib import Path
from typing import Optional


def load_environment():
    """Load environment variables from .env file"""
    try:
        # Try to import dotenv
        try:
            from dotenv import load_dotenv
            
            # Load from standard locations
            load_dotenv()  # Load from .env in current directory
            
            # Also try to load from Triksha-specific locations
            triksha_env = Path.home() / "triksha" / ".env"
            if triksha_env.exists():
                load_dotenv(dotenv_path=triksha_env)
                
        except ImportError:
            # Dotenv not installed, try manual loading
            env_file = Path.home() / "triksha" / ".env"
            if env_file.exists():
                with open(env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            os.environ[key.strip()] = value.strip().strip('"\'')
    except Exception:
        # Silently continue if loading environment variables fails
        pass


def get_api_key(service: str, verbose: bool = False) -> Optional[str]:
    """Get API key for a service from environment variables"""
    service_upper = service.upper()
    
    # Common environment variable names for different services
    env_vars = {
        'openai': ['OPENAI_API_KEY', 'OPENAI_KEY'],
        'google': ['GOOGLE_API_KEY', 'GEMINI_API_KEY', 'GOOGLE_KEY'],
        'gemini': ['GEMINI_API_KEY', 'GOOGLE_API_KEY', 'GEMINI_KEY'],
        'huggingface': ['HUGGINGFACE_API_KEY', 'HF_TOKEN', 'HUGGINGFACE_TOKEN'],
        'anthropic': ['ANTHROPIC_API_KEY', 'ANTHROPIC_KEY'],
        'proxy': ['GEMINI_API_KEY', 'GEMINI_KEY']
    }
    
    # Get possible environment variable names
    possible_vars = env_vars.get(service.lower(), [f"{service_upper}_API_KEY", f"{service_upper}_KEY"])
    
    # Try each possible environment variable
    for var_name in possible_vars:
        api_key = os.getenv(var_name)
        if api_key:
            if verbose:
                print(f"Found {service} API key in {var_name}")
            return api_key
    
    if verbose:
        print(f"No API key found for {service}. Tried: {possible_vars}")
    
    return None


def get_playground_rate_limits() -> dict:
    """Get playground rate limit configuration from environment variables"""
    return {
        "requests_per_minute": int(os.getenv("PLAYGROUND_RPM_LIMIT", "10")),
        "requests_per_hour": int(os.getenv("PLAYGROUND_RPH_LIMIT", "50")),
        "max_concurrent_requests": int(os.getenv("PLAYGROUND_CONCURRENT_LIMIT", "2")),
        "daily_limit": int(os.getenv("PLAYGROUND_DAILY_LIMIT", "200")),
        "cooldown_seconds": int(os.getenv("PLAYGROUND_COOLDOWN_SECONDS", "5"))
    }