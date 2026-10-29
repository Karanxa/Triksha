"""
Authentication and authorization module for Triksha API.

This module handles API key validation, rate limiting, and user management.
"""

import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from pathlib import Path
import json

from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


class APIKeyManager:
    """Manages API keys and authentication"""
    
    def __init__(self, config_dir: Optional[str] = None):
        """Initialize API key manager"""
        self.config_dir = Path(config_dir or Path.home() / "triksha" / "api")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.keys_file = self.config_dir / "api_keys.json"
        self.rate_limits_file = self.config_dir / "rate_limits.json"
        
        # Load existing keys and rate limit data
        self.api_keys = self._load_api_keys()
        self.rate_limits = self._load_rate_limits()
        
        # Rate limiting configuration
        self.default_rate_limit = {
            "requests_per_minute": 100,
            "max_concurrent_scans": 10,
            "max_prompt_count": 1000
        }
    
    def _load_api_keys(self) -> Dict[str, Dict]:
        """Load API keys from file"""
        if self.keys_file.exists():
            try:
                with open(self.keys_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def _save_api_keys(self):
        """Save API keys to file"""
        try:
            with open(self.keys_file, 'w') as f:
                json.dump(self.api_keys, f, indent=2)
        except Exception as e:
            print(f"Error saving API keys: {e}")
    
    def _load_rate_limits(self) -> Dict[str, Dict]:
        """Load rate limit data from file"""
        if self.rate_limits_file.exists():
            try:
                with open(self.rate_limits_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def _save_rate_limits(self):
        """Save rate limit data to file"""
        try:
            with open(self.rate_limits_file, 'w') as f:
                json.dump(self.rate_limits, f, indent=2)
        except Exception as e:
            print(f"Error saving rate limits: {e}")
    
    def create_api_key(
        self, 
        name: str, 
        description: str = "",
        rate_limit_override: Optional[Dict] = None
    ) -> str:
        """Create a new API key"""
        # Generate secure API key
        api_key = "triksha_" + secrets.token_urlsafe(32)
        
        # Hash the key for storage
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Store key metadata
        self.api_keys[key_hash] = {
            "name": name,
            "description": description,
            "created_at": datetime.utcnow().isoformat(),
            "last_used": None,
            "usage_count": 0,
            "rate_limits": rate_limit_override or self.default_rate_limit,
            "active": True
        }
        
        self._save_api_keys()
        return api_key
    
    def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """Validate an API key and return key metadata"""
        if not api_key or not api_key.startswith("triksha_"):
            return None
        
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        if key_hash not in self.api_keys:
            return None
        
        key_data = self.api_keys[key_hash]
        
        if not key_data.get("active", True):
            return None
        
        # Update usage statistics
        key_data["last_used"] = datetime.utcnow().isoformat()
        key_data["usage_count"] = key_data.get("usage_count", 0) + 1
        self._save_api_keys()
        
        return {
            "key_hash": key_hash,
            "name": key_data["name"],
            "rate_limits": key_data.get("rate_limits", self.default_rate_limit)
        }
    
    def check_rate_limit(self, key_hash: str) -> bool:
        """Check if API key is within rate limits"""
        current_time = time.time()
        minute_window = int(current_time // 60)
        
        # Initialize rate limit data for this key if not exists
        if key_hash not in self.rate_limits:
            self.rate_limits[key_hash] = {
                "current_minute": minute_window,
                "requests_this_minute": 0,
                "concurrent_scans": 0
            }
        
        rate_data = self.rate_limits[key_hash]
        key_info = self.api_keys.get(key_hash, {})
        limits = key_info.get("rate_limits", self.default_rate_limit)
        
        # Reset counter if we're in a new minute
        if rate_data["current_minute"] != minute_window:
            rate_data["current_minute"] = minute_window
            rate_data["requests_this_minute"] = 0
        
        # Check requests per minute limit
        if rate_data["requests_this_minute"] >= limits["requests_per_minute"]:
            return False
        
        # Increment request counter
        rate_data["requests_this_minute"] += 1
        self._save_rate_limits()
        
        return True
    
    def increment_concurrent_scans(self, key_hash: str) -> bool:
        """Increment concurrent scan count, return False if limit exceeded"""
        if key_hash not in self.rate_limits:
            self.rate_limits[key_hash] = {
                "current_minute": int(time.time() // 60),
                "requests_this_minute": 0,
                "concurrent_scans": 0
            }
        
        rate_data = self.rate_limits[key_hash]
        key_info = self.api_keys.get(key_hash, {})
        limits = key_info.get("rate_limits", self.default_rate_limit)
        
        if rate_data["concurrent_scans"] >= limits["max_concurrent_scans"]:
            return False
        
        rate_data["concurrent_scans"] += 1
        self._save_rate_limits()
        return True
    
    def decrement_concurrent_scans(self, key_hash: str):
        """Decrement concurrent scan count"""
        if key_hash in self.rate_limits:
            self.rate_limits[key_hash]["concurrent_scans"] = max(
                0, 
                self.rate_limits[key_hash]["concurrent_scans"] - 1
            )
            self._save_rate_limits()
    
    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        if key_hash in self.api_keys:
            self.api_keys[key_hash]["active"] = False
            self.api_keys[key_hash]["revoked_at"] = datetime.utcnow().isoformat()
            self._save_api_keys()
            return True
        
        return False
    
    def list_api_keys(self) -> List[Dict]:
        """List all API keys (without revealing the actual keys)"""
        keys = []
        for key_hash, key_data in self.api_keys.items():
            keys.append({
                "name": key_data["name"],
                "description": key_data.get("description", ""),
                "created_at": key_data["created_at"],
                "last_used": key_data.get("last_used"),
                "usage_count": key_data.get("usage_count", 0),
                "active": key_data.get("active", True),
                "rate_limits": key_data.get("rate_limits", self.default_rate_limit)
            })
        return keys


# Global API key manager instance
api_key_manager = APIKeyManager()


class TrikshaHTTPBearer(HTTPBearer):
    """Custom HTTP Bearer authentication with rate limiting"""
    
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)
    
    async def __call__(self, request) -> str:
        """Authenticate request and return key hash"""
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        
        if not credentials or credentials.scheme != "Bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Validate API key
        key_info = api_key_manager.validate_api_key(credentials.credentials)
        if not key_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check rate limits
        if not api_key_manager.check_rate_limit(key_info["key_hash"]):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(key_info["rate_limits"]["requests_per_minute"]),
                    "X-RateLimit-Remaining": "0"
                }
            )
        
        return key_info["key_hash"]


# Create security dependency
security = TrikshaHTTPBearer()


def check_scan_limits(key_hash: str, prompt_count: int) -> bool:
    """Check if scan parameters are within limits for the API key"""
    key_info = api_key_manager.api_keys.get(key_hash, {})
    limits = key_info.get("rate_limits", api_key_manager.default_rate_limit)
    
    # Check prompt count limit
    if prompt_count > limits["max_prompt_count"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Prompt count {prompt_count} exceeds limit of {limits['max_prompt_count']}"
        )
    
    # Check concurrent scan limit
    if not api_key_manager.increment_concurrent_scans(key_hash):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum concurrent scans limit reached ({limits['max_concurrent_scans']})"
        )
    
    return True