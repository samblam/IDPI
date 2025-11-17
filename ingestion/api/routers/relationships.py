"""
Relationships Router

Endpoints for querying indicator relationships
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request

from api.services.query_service import QueryService
from api.middleware.auth import get_api_key
from api.models.responses import RelationshipsResponse


router = APIRouter(prefix="/relationships", tags=["Relationships"])
query_service = QueryService()


@router.get(
    "",
    response_model=RelationshipsResponse,
    summary="Query relationships",
    description="Query relationships between indicators"
)
async def query_relationships(
    request: Request,
    indicator_id: Optional[str] = Query(None, description="Filter by source or target indicator ID"),
    relationship_type: Optional[str] = Query(None, description="Filter by relationship type"),
    api_key_metadata: dict = Depends(get_api_key)
):
    """
    Query indicator relationships

    Returns relationships between indicators (e.g., domain resolves_to IP)
    """
    result = await query_service.query_relationships(
        indicator_id=indicator_id,
        relationship_type=relationship_type
    )

    return RelationshipsResponse(
        items=result["items"],
        count=len(result["items"])
    )
