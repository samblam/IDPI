"""
API Response Models

Pydantic models for API responses
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class IndicatorResponse(BaseModel):
    """Single indicator response"""
    id: str
    indicator_value: str
    indicator_type: str
    confidence_score: int
    source_count: int
    sources: List[Dict[str, Any]]
    enrichment: Optional[Dict[str, Any]] = None
    enriched_at: Optional[str] = None
    created_at: str
    updated_at: str


class PaginatedIndicatorsResponse(BaseModel):
    """Paginated indicators response"""
    items: List[IndicatorResponse]
    continuation_token: Optional[str] = None
    count: int = Field(description="Number of items in this page")


class RelationshipResponse(BaseModel):
    """Single relationship response"""
    id: str
    source_id: str
    target_id: str
    relationship_type: str
    confidence: float
    detected_at: str


class RelationshipsResponse(BaseModel):
    """Relationships response"""
    items: List[RelationshipResponse]
    count: int


class StatisticsResponse(BaseModel):
    """Statistics response"""
    total_indicators: int
    by_type: Dict[str, int]
    last_updated: Optional[str] = None


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    version: str = "1.0.0"
