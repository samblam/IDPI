"""
Rate Limiting Middleware

Per-API-key rate limiting with tier support
"""
import os
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request


def get_api_key_identifier(request: Request) -> str:
    """
    Get API key from request for rate limiting

    Uses API key from request state (set by auth middleware)
    Falls back to IP address if no API key

    Args:
        request: FastAPI request

    Returns:
        Identifier for rate limiting
    """
    # Get API key from request state (set by auth middleware)
    api_key = getattr(request.state, "api_key", None)

    if api_key:
        return f"api_key:{api_key}"

    # Fallback to IP address
    return f"ip:{get_remote_address(request)}"


def get_rate_limit_for_key(request: Request) -> str:
    """
    Get rate limit based on API key tier

    Reads tier from request state metadata and returns appropriate limit

    Args:
        request: FastAPI request

    Returns:
        Rate limit string (e.g., "60/minute")
    """
    metadata = getattr(request.state, "api_key_metadata", None)

    if metadata:
        # Get tier-specific limit
        tier = metadata.get("tier", "free")
        rate_limit = metadata.get("rate_limit_per_minute", 10)
        return f"{rate_limit}/minute"

    # Default for unauthenticated requests
    return "10/minute"


# Initialize limiter with configurable Redis URI
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = os.getenv("REDIS_PORT", "6379")
storage_uri = f"redis://{redis_host}:{redis_port}"

limiter = Limiter(
    key_func=get_api_key_identifier,
    default_limits=["1000/hour", "60/minute"],
    storage_uri=storage_uri,
    storage_options={"socket_connect_timeout": 30},
    strategy="fixed-window"
)


# Tier-based rate limit decorators
def tier_based_limit(request: Request) -> str:
    """
    Dynamic rate limit based on API key tier

    Args:
        request: FastAPI request

    Returns:
        Rate limit string
    """
    return get_rate_limit_for_key(request)
