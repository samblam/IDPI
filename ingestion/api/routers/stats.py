"""
Statistics Router

Endpoints for platform statistics
"""
from fastapi import APIRouter, Depends, Request

from api.services.query_service import QueryService
from api.middleware.auth import get_api_key
from api.models.responses import StatisticsResponse


router = APIRouter(prefix="/stats", tags=["Statistics"])
query_service = QueryService()


@router.get(
    "",
    response_model=StatisticsResponse,
    summary="Get statistics",
    description="Get platform-wide statistics about indicators"
)
async def get_statistics(
    request: Request,
    api_key_metadata: dict = Depends(get_api_key)
):
    """
    Get platform statistics

    Returns counts of indicators by type and other metrics.
    Results are cached for performance.
    """
    stats = await query_service.get_statistics()

    return StatisticsResponse(
        total_indicators=stats["total_indicators"],
        by_type=stats["by_type"],
        last_updated=None  # Could add timestamp from cache
    )
