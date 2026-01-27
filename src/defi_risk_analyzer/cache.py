"""Simple file-based cache with TTL for API responses."""
import hashlib
import json
import time
from pathlib import Path
from typing import Any


class FileCache:
    """File-based cache with time-to-live (TTL) support.
    
    Stores cache entries as JSON files in a dedicated directory.
    Each entry includes timestamp for TTL validation.
    """
    
    def __init__(self, cache_dir: str = ".cache", ttl_seconds: int = 3600):
        """Initialize cache.
        
        Args:
            cache_dir: Directory to store cache files (default: .cache)
            ttl_seconds: Time-to-live in seconds (default: 3600 = 1 hour)
        """
        self.cache_dir = Path(cache_dir)
        self.ttl_seconds = ttl_seconds
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def get(self, key: str) -> Any | None:
        """Retrieve value from cache if not expired.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value if valid, None if expired or not found
        """
        cache_file = self._get_cache_file(key)
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                entry = json.load(f)
            
            timestamp = entry.get("timestamp", 0)
            if time.time() - timestamp > self.ttl_seconds:
                # Cache expired
                cache_file.unlink(missing_ok=True)
                return None
            
            return entry.get("value")
        except (json.JSONDecodeError, OSError):
            # Corrupted cache file
            cache_file.unlink(missing_ok=True)
            return None
    
    def set(self, key: str, value: Any) -> None:
        """Store value in cache with current timestamp.
        
        Args:
            key: Cache key
            value: Value to cache (must be JSON-serializable)
        """
        cache_file = self._get_cache_file(key)
        entry = {
            "timestamp": time.time(),
            "value": value,
        }
        
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(entry, f)
        except (TypeError, OSError):
            # Value not serializable or write error
            pass
    
    def clear(self) -> None:
        """Remove all cache files."""
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink(missing_ok=True)
    
    def _get_cache_file(self, key: str) -> Path:
        """Generate cache file path from key using hash."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"
