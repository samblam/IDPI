"""
Intelligence Data Pipeline - Query API

FastAPI application for querying threat intelligence data
"""
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from datetime import datetime, timezone

from api.routers import indicators, relationships, stats, streaming
from api.middleware.auth import APIKeyMiddleware
from api.middleware.rate_limit import limiter, _rate_limit_exceeded_handler
from api.models.responses import HealthResponse, ErrorResponse


# Create FastAPI application
app = FastAPI(
    title="Intelligence Data Pipeline API",
    description="Query API for threat intelligence indicators with enrichment data",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add rate limiter state
app.state.limiter = limiter

# Add rate limit exceeded handler
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure based on deployment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add API key authentication middleware
app.add_middleware(
    APIKeyMiddleware,
    exclude_paths=["/health", "/docs", "/redoc", "/openapi.json"]
)

# Include routers
app.include_router(indicators.router)
app.include_router(relationships.router)
app.include_router(stats.router)
app.include_router(streaming.router)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check",
    description="Check API health status"
)
async def health_check():
    """
    Health check endpoint

    Does not require authentication
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc).isoformat(),
        version="1.0.0"
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler

    Catches all unhandled exceptions and returns JSON error response
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="Internal server error",
            detail=str(exc) if app.debug else "An unexpected error occurred"
        ).model_dump()
    )


@app.on_event("startup")
async def startup_event():
    """Startup event handler"""
    print("=" * 60)
    print("Intelligence Data Pipeline API Starting")
    print("=" * 60)
    print(f"Environment: {app.debug and 'Development' or 'Production'}")
    print(f"Docs: {app.docs_url}")
    print("=" * 60)


@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler"""
    print("API shutting down...")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
