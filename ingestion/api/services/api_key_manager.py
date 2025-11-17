"""
API Key Manager

Manages API key validation, metadata, and usage tracking
"""
from typing import Dict, Optional
from datetime import datetime, timezone
from enum import Enum
import logging

from storage.cosmos_client import CosmosClient


class APIKeyTier(Enum):
    """API key tier levels"""
    FREE = "free"
    STANDARD = "standard"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


class APIKeyManager:
    """
    Manages API key validation and tracking

    Validates API keys against Cosmos DB, retrieves metadata,
    and tracks usage statistics.
    """

    def __init__(self):
        """Initialize API Key Manager"""
        self.cosmos_client = CosmosClient()
        self.container = "api_keys"
        self.usage_container = "api_usage"
        self.logger = logging.getLogger(self.__class__.__name__)

    async def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """
        Validate API key and return metadata

        Args:
            api_key: API key to validate

        Returns:
            API key metadata if valid and enabled, None otherwise
        """
        try:
            # Get API key from Cosmos DB
            key_data = self.cosmos_client.get_item(self.container, api_key)

            if not key_data:
                self.logger.warning(f"API key not found: {api_key[:8]}...")
                return None

            # Check if key is enabled
            if not key_data.get("enabled", False):
                self.logger.warning(f"API key is disabled: {api_key[:8]}...")
                return None

            return key_data

        except Exception as e:
            self.logger.error(f"Error validating API key: {e}", exc_info=True)
            return None

    async def get_metadata(self, api_key: str) -> Optional[Dict]:
        """
        Get complete API key metadata

        Args:
            api_key: API key to get metadata for

        Returns:
            Complete API key metadata, or None if key doesn't exist
        """
        try:
            return self.cosmos_client.get_item(self.container, api_key)
        except Exception as e:
            self.logger.error(f"Error getting API key metadata: {e}", exc_info=True)
            return None

    async def record_usage(self, api_key: str, endpoint: str) -> None:
        """
        Record API key usage

        Args:
            api_key: API key that made the request
            endpoint: Endpoint that was called
        """
        try:
            # Create usage record
            usage_record = {
                "id": f"{api_key}_{datetime.now(timezone.utc).isoformat()}",
                "api_key": api_key,
                "endpoint": endpoint,
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            }

            # Upsert usage record
            self.cosmos_client.upsert_item(self.usage_container, usage_record)

        except Exception as e:
            # Don't fail requests due to usage tracking errors
            self.logger.error(f"Error recording API usage: {e}", exc_info=True)
