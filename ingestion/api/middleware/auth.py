"""
API Key Authentication Middleware

Validates API keys for all protected endpoints
"""
from typing import Optional
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from api.services.api_key_manager import APIKeyManager


# API Key header configuration
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_api_key(
    api_key: Optional[str] = Security(api_key_header)
) -> dict:
    """
    Validate API key and return metadata

    Args:
        api_key: API key from X-API-Key header

    Returns:
        API key metadata

    Raises:
        HTTPException: If API key is invalid or missing
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Provide via X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    manager = APIKeyManager()
    metadata = await manager.validate_api_key(api_key)

    if not metadata:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or disabled API key"
        )

    return metadata


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate API keys for all requests

    Adds API key metadata to request state for use in endpoints
    """

    def __init__(self, app, exclude_paths: Optional[list] = None):
        """
        Initialize middleware

        Args:
            app: FastAPI application
            exclude_paths: List of paths to exclude from auth (e.g., /health, /docs)
        """
        super().__init__(app)
        self.exclude_paths = exclude_paths or [
            "/health",
            "/docs",
            "/openapi.json",
            "/redoc"
        ]

    async def dispatch(self, request: Request, call_next):
        """
        Process request and validate API key

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response
        """
        # Skip auth for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Get API key from header
        api_key = request.headers.get("X-API-Key")

        if not api_key:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": "API key required",
                    "detail": "Provide X-API-Key header"
                }
            )

        # Validate API key
        manager = APIKeyManager()
        metadata = await manager.validate_api_key(api_key)

        if not metadata:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "Invalid API key",
                    "detail": "API key is invalid or disabled"
                }
            )

        # Add metadata to request state
        request.state.api_key = api_key
        request.state.api_key_metadata = metadata

        # Record usage (non-blocking)
        try:
            await manager.record_usage(api_key, request.url.path)
        except Exception:
            pass  # Don't fail request if usage tracking fails

        response = await call_next(request)
        return response
