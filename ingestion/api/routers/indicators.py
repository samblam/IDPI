"""
Indicators Router

Endpoints for querying and searching threat indicators
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from slowapi import Limiter

from api.services.query_service import QueryService
from api.middleware.auth import get_api_key
from api.middleware.rate_limit import tier_based_limit
from api.models.responses import IndicatorResponse, PaginatedIndicatorsResponse, ErrorResponse


router = APIRouter(prefix="/indicators", tags=["Indicators"])
query_service = QueryService()


@router.get(
    "",
    response_model=PaginatedIndicatorsResponse,
    summary="Query indicators",
    description="Query threat indicators with optional filtering and pagination"
)
async def query_indicators(
    request: Request,
    indicator_type: Optional[str] = Query(None, description="Filter by indicator type"),
    confidence_min: Optional[int] = Query(None, ge=0, le=100, description="Minimum confidence score"),
    page_size: Optional[int] = Query(100, ge=1, le=1000, description="Items per page"),
    continuation_token: Optional[str] = Query(None, description="Pagination continuation token"),
    api_key_metadata: dict = Depends(get_api_key)
):
    """
    Query threat indicators

    Supports filtering by type and confidence, with pagination
    """
    result = await query_service.query_indicators(
        indicator_type=indicator_type,
        confidence_min=confidence_min,
        page_size=page_size,
        continuation_token=continuation_token
    )

    return PaginatedIndicatorsResponse(
        items=result["items"],
        continuation_token=result.get("continuation_token"),
        count=len(result["items"])
    )


@router.get(
    "/search",
    response_model=PaginatedIndicatorsResponse,
    summary="Search indicators",
    description="Full-text search across indicator values"
)
async def search_indicators(
    request: Request,
    q: str = Query(..., min_length=1, description="Search query"),
    page_size: Optional[int] = Query(100, ge=1, le=1000, description="Items per page"),
    api_key_metadata: dict = Depends(get_api_key)
):
    """
    Search indicators by value

    Uses parameterized queries to prevent SQL injection
    """
    result = await query_service.search_indicators(
        search_term=q,
        page_size=page_size
    )

    return PaginatedIndicatorsResponse(
        items=result["items"],
        continuation_token=None,
        count=len(result["items"])
    )


@router.get(
    "/{indicator_id}",
    response_model=IndicatorResponse,
    summary="Get indicator by ID",
    description="Retrieve a specific indicator by its ID",
    responses={404: {"model": ErrorResponse, "description": "Indicator not found"}}
)
async def get_indicator(
    request: Request,
    indicator_id: str,
    api_key_metadata: dict = Depends(get_api_key)
):
    """
    Get indicator by ID

    Returns full indicator details including enrichment data
    """
    indicator = await query_service.get_indicator_by_id(indicator_id)

    if not indicator:
        raise HTTPException(
            status_code=404,
            detail=f"Indicator not found: {indicator_id}"
        )

    return indicator
