"""
API Request Models

Pydantic models for API request validation
"""
from typing import Optional
from pydantic import BaseModel, Field, validator


class IndicatorQueryParams(BaseModel):
    """Query parameters for indicator search"""
    indicator_type: Optional[str] = Field(None, description="Filter by indicator type")
    confidence_min: Optional[int] = Field(None, ge=0, le=100, description="Minimum confidence score")
    page_size: Optional[int] = Field(100, ge=1, le=1000, description="Items per page")
    continuation_token: Optional[str] = Field(None, description="Pagination token")

    @validator('indicator_type')
    def validate_indicator_type(cls, v):
        """Validate indicator type"""
        if v is not None:
            allowed_types = ['domain', 'IPv4', 'IPv6', 'url', 'hash', 'email']
            if v not in allowed_types:
                raise ValueError(f"Invalid indicator type. Must be one of: {allowed_types}")
        return v


class SearchQueryParams(BaseModel):
    """Query parameters for search"""
    q: str = Field(..., min_length=1, description="Search query")
    page_size: Optional[int] = Field(100, ge=1, le=1000, description="Items per page")


class RelationshipQueryParams(BaseModel):
    """Query parameters for relationships"""
    indicator_id: Optional[str] = Field(None, description="Filter by indicator ID")
    relationship_type: Optional[str] = Field(None, description="Filter by relationship type")

    @validator('relationship_type')
    def validate_relationship_type(cls, v):
        """Validate relationship type"""
        if v is not None:
            allowed_types = ['resolves_to', 'downloads', 'communicates_with', 'contains']
            if v not in allowed_types:
                raise ValueError(f"Invalid relationship type. Must be one of: {allowed_types}")
        return v
