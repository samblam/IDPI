"""
Tests for API Key Manager

Following TDD - Tests written FIRST
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone, timedelta

from api.services.api_key_manager import APIKeyManager, APIKeyTier


@pytest.mark.unit
class TestAPIKeyManagerValidation:
    """Test API key validation"""

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_validate_valid_api_key_returns_metadata(self, mock_cosmos_class):
        """Should return metadata for valid API key"""
        mock_client = Mock()
        mock_client.get_item.return_value = {
            "id": "test-key-123",
            "api_key": "test-key-123",
            "tier": "standard",
            "rate_limit_per_minute": 60,
            "enabled": True,
            "created_at": "2024-01-01T00:00:00Z"
        }
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        result = await manager.validate_api_key("test-key-123")

        assert result is not None
        assert result["api_key"] == "test-key-123"
        assert result["tier"] == "standard"
        assert result["rate_limit_per_minute"] == 60
        assert result["enabled"] is True

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_validate_invalid_api_key_returns_none(self, mock_cosmos_class):
        """Should return None for invalid API key"""
        mock_client = Mock()
        mock_client.get_item.return_value = None
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        result = await manager.validate_api_key("invalid-key")

        assert result is None

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_validate_disabled_api_key_returns_none(self, mock_cosmos_class):
        """Should return None for disabled API key"""
        mock_client = Mock()
        mock_client.get_item.return_value = {
            "id": "disabled-key",
            "api_key": "disabled-key",
            "tier": "free",
            "enabled": False
        }
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        result = await manager.validate_api_key("disabled-key")

        assert result is None

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_validate_handles_cosmos_errors(self, mock_cosmos_class):
        """Should handle Cosmos DB errors gracefully"""
        mock_client = Mock()
        mock_client.get_item.side_effect = Exception("Cosmos DB error")
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        result = await manager.validate_api_key("test-key")

        assert result is None


@pytest.mark.unit
class TestAPIKeyTiers:
    """Test API key tier functionality"""

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_free_tier_has_correct_limits(self, mock_cosmos_class):
        """Should return correct limits for free tier"""
        mock_client = Mock()
        mock_client.get_item.return_value = {
            "id": "free-key",
            "api_key": "free-key",
            "tier": "free",
            "rate_limit_per_minute": 10,
            "enabled": True
        }
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        metadata = await manager.validate_api_key("free-key")

        assert metadata["tier"] == "free"
        assert metadata["rate_limit_per_minute"] == 10

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_standard_tier_has_correct_limits(self, mock_cosmos_class):
        """Should return correct limits for standard tier"""
        mock_client = Mock()
        mock_client.get_item.return_value = {
            "id": "standard-key",
            "api_key": "standard-key",
            "tier": "standard",
            "rate_limit_per_minute": 60,
            "enabled": True
        }
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        metadata = await manager.validate_api_key("standard-key")

        assert metadata["tier"] == "standard"
        assert metadata["rate_limit_per_minute"] == 60

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_premium_tier_has_correct_limits(self, mock_cosmos_class):
        """Should return correct limits for premium tier"""
        mock_client = Mock()
        mock_client.get_item.return_value = {
            "id": "premium-key",
            "api_key": "premium-key",
            "tier": "premium",
            "rate_limit_per_minute": 300,
            "enabled": True
        }
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        metadata = await manager.validate_api_key("premium-key")

        assert metadata["tier"] == "premium"
        assert metadata["rate_limit_per_minute"] == 300

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_enterprise_tier_has_correct_limits(self, mock_cosmos_class):
        """Should return correct limits for enterprise tier"""
        mock_client = Mock()
        mock_client.get_item.return_value = {
            "id": "enterprise-key",
            "api_key": "enterprise-key",
            "tier": "enterprise",
            "rate_limit_per_minute": 1000,
            "enabled": True
        }
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        metadata = await manager.validate_api_key("enterprise-key")

        assert metadata["tier"] == "enterprise"
        assert metadata["rate_limit_per_minute"] == 1000


@pytest.mark.unit
class TestAPIKeyUsageTracking:
    """Test API key usage tracking"""

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_record_usage_increments_counters(self, mock_cosmos_class):
        """Should increment usage counters"""
        mock_client = Mock()
        mock_client.upsert_item = Mock()
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        await manager.record_usage("test-key", endpoint="/api/indicators")

        # Verify upsert was called
        assert mock_client.upsert_item.called

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_record_usage_tracks_endpoint(self, mock_cosmos_class):
        """Should track which endpoint was called"""
        mock_client = Mock()
        mock_client.upsert_item = Mock()
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        await manager.record_usage("test-key", endpoint="/api/relationships")

        call_args = mock_client.upsert_item.call_args
        usage_record = call_args[0][1]
        assert usage_record["endpoint"] == "/api/relationships"

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_record_usage_includes_timestamp(self, mock_cosmos_class):
        """Should include timestamp in usage record"""
        mock_client = Mock()
        mock_client.upsert_item = Mock()
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        before = datetime.now(timezone.utc)
        await manager.record_usage("test-key", endpoint="/api/stats")
        after = datetime.now(timezone.utc)

        call_args = mock_client.upsert_item.call_args
        usage_record = call_args[0][1]

        timestamp = datetime.fromisoformat(usage_record["timestamp"].replace('Z', '+00:00'))
        assert before <= timestamp <= after

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_record_usage_handles_errors(self, mock_cosmos_class):
        """Should handle Cosmos DB errors gracefully during usage tracking"""
        mock_client = Mock()
        mock_client.upsert_item.side_effect = Exception("Cosmos error")
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        # Should not raise exception
        await manager.record_usage("test-key", endpoint="/api/test")


@pytest.mark.unit
class TestGetAPIKeyMetadata:
    """Test retrieving API key metadata"""

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_get_metadata_returns_complete_info(self, mock_cosmos_class):
        """Should return complete API key metadata"""
        mock_client = Mock()
        mock_client.get_item.return_value = {
            "id": "test-key",
            "api_key": "test-key",
            "tier": "premium",
            "rate_limit_per_minute": 300,
            "enabled": True,
            "created_at": "2024-01-01T00:00:00Z",
            "owner": "test@example.com",
            "description": "Test API key"
        }
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        metadata = await manager.get_metadata("test-key")

        assert metadata["tier"] == "premium"
        assert metadata["rate_limit_per_minute"] == 300
        assert metadata["owner"] == "test@example.com"
        assert metadata["description"] == "Test API key"

    @patch('api.services.api_key_manager.CosmosClient')
    async def test_get_metadata_for_nonexistent_key_returns_none(self, mock_cosmos_class):
        """Should return None for nonexistent API key"""
        mock_client = Mock()
        mock_client.get_item.return_value = None
        mock_cosmos_class.return_value = mock_client

        manager = APIKeyManager()
        metadata = await manager.get_metadata("nonexistent")

        assert metadata is None


@pytest.mark.unit
class TestAPIKeyTierEnum:
    """Test API key tier enumeration"""

    def test_tier_enum_has_all_tiers(self):
        """Should have all expected tier levels"""
        assert hasattr(APIKeyTier, 'FREE')
        assert hasattr(APIKeyTier, 'STANDARD')
        assert hasattr(APIKeyTier, 'PREMIUM')
        assert hasattr(APIKeyTier, 'ENTERPRISE')

    def test_tier_enum_values(self):
        """Should have correct tier values"""
        assert APIKeyTier.FREE.value == "free"
        assert APIKeyTier.STANDARD.value == "standard"
        assert APIKeyTier.PREMIUM.value == "premium"
        assert APIKeyTier.ENTERPRISE.value == "enterprise"
