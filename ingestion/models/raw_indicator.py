"""
Pydantic model for raw threat indicators

This model validates and stores indicators as they are ingested from sources
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from enum import Enum


class IndicatorType(str, Enum):
    """Valid indicator types"""
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "URL"
    MD5 = "FileHash-MD5"
    SHA256 = "FileHash-SHA256"


class RawIndicator(BaseModel):
    """
    Raw indicator from threat intelligence source

    This model represents an indicator before normalization and deduplication
    """

    source: str = Field(
        ...,
        description="Source of the indicator (otx, abuseipdb, urlhaus)",
        examples=["otx", "abuseipdb", "urlhaus"]
    )

    indicator_value: str = Field(
        ...,
        description="The actual indicator value (IP, domain, hash, etc.)",
        examples=["1.2.3.4", "malicious.com", "abc123..."]
    )

    indicator_type: IndicatorType = Field(
        ...,
        description="Type of indicator"
    )

    confidence: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Confidence score 0-100"
    )

    tags: List[str] = Field(
        default_factory=list,
        description="Tags associated with the indicator"
    )

    ingested_at: str = Field(
        ...,
        description="ISO8601 timestamp when indicator was ingested"
    )

    raw_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Original metadata from source API"
    )

    model_config = ConfigDict(
        use_enum_values=True,  # Serialize enum as string value
        json_schema_extra={
            "example": {
                "source": "otx",
                "indicator_value": "1.2.3.4",
                "indicator_type": "IPv4",
                "confidence": 75,
                "tags": ["malware", "botnet"],
                "ingested_at": "2024-01-01T12:00:00Z",
                "raw_metadata": {
                    "pulse_id": "123abc",
                    "pulse_name": "Malicious Campaign",
                    "tlp": "white"
                }
            }
        }
    )
