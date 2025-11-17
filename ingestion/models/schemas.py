"""
Pydantic schemas for API response validation

These schemas validate responses from external threat intel APIs
"""
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional
from enum import Enum


class OTXIndicatorType(str, Enum):
    """Valid OTX indicator types"""
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "URL"
    MD5 = "FileHash-MD5"
    SHA256 = "FileHash-SHA256"


class OTXIndicatorSchema(BaseModel):
    """Pydantic schema for OTX API indicator validation"""

    indicator: str = Field(..., description="The indicator value")
    type: OTXIndicatorType = Field(..., description="Indicator type")
    description: Optional[str] = Field(default="", description="Description of the indicator")

    @field_validator('type')
    @classmethod
    def validate_indicator_type(cls, v):
        """Validate indicator type is in allowed list"""
        valid_types = ['IPv4', 'IPv6', 'domain', 'hostname', 'URL', 'FileHash-MD5', 'FileHash-SHA256']
        if v not in valid_types:
            raise ValueError(f'Invalid indicator type: {v}. Must be one of {valid_types}')
        return v

    model_config = ConfigDict(use_enum_values=True)


class OTXPulseSchema(BaseModel):
    """Pydantic schema for OTX pulse validation"""

    id: str = Field(..., description="Pulse ID")
    name: str = Field(..., description="Pulse name")
    TLP: Optional[str] = Field(default="unknown", description="Traffic Light Protocol")
    tags: List[str] = Field(default_factory=list, description="Associated tags")
    indicators: List[OTXIndicatorSchema] = Field(default_factory=list, description="List of indicators")
    description: Optional[str] = Field(default="", description="Pulse description")

    model_config = ConfigDict(
        extra='allow',  # Allow extra fields from API (forward compatibility)
        use_enum_values=True
    )


class AbuseIPDBDataSchema(BaseModel):
    """Pydantic schema for AbuseIPDB API data validation"""

    ipAddress: str = Field(..., description="IP address")
    abuseConfidenceScore: int = Field(
        ...,
        ge=0,
        le=100,
        description="Abuse confidence score (0-100)"
    )
    totalReports: int = Field(..., ge=0, description="Total number of reports")
    lastReportedAt: Optional[str] = Field(default=None, description="Last reported timestamp")

    model_config = ConfigDict(extra='allow')  # Allow extra fields


class URLhausEntrySchema(BaseModel):
    """Pydantic schema for URLhaus API entry validation"""

    url: str = Field(..., description="Malicious URL")
    url_status: str = Field(..., description="URL status (online, offline, etc.)")
    threat: Optional[str] = Field(default=None, description="Threat type")
    tags: List[str] = Field(default_factory=list, description="Associated tags")

    model_config = ConfigDict(extra='allow')
