"""
API Integration Tests

Tests complete API workflows with all components integrated
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, AsyncMock, patch

from api.main import app


@pytest.mark.integration
class TestAPIAuthentication:
    """Test API authentication workflows"""

    @patch('api.middleware.auth.APIKeyManager')
    def test_health_endpoint_no_auth_required(self, mock_manager_class):
        """Should allow health check without API key"""
        client = TestClient(app)

        response = client.get("/health")

        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
        # APIKeyManager should not be called for health endpoint
        assert not mock_manager_class.called

    @patch('api.services.query_service.CosmosClient')
    @patch('api.services.query_service.CacheService')
    @patch('api.middleware.auth.APIKeyManager')
    def test_indicators_endpoint_requires_auth(
        self,
        mock_manager_class,
        mock_cache_class,
        mock_cosmos_class
    ):
        """Should require API key for indicators endpoint"""
        client = TestClient(app)

        # Request without API key
        response = client.get("/indicators")

        assert response.status_code == 401
        assert "API key required" in response.json()["error"]

    @patch('api.services.query_service.CosmosClient')
    @patch('api.services.query_service.CacheService')
    @patch('api.middleware.auth.APIKeyManager')
    def test_valid_api_key_grants_access(
        self,
        mock_manager_class,
        mock_cache_class,
        mock_cosmos_class
    ):
        """Should allow access with valid API key"""
        # Mock valid API key
        mock_manager = Mock()
        mock_manager.validate_api_key = AsyncMock(return_value={
            "api_key": "valid-key",
            "tier": "standard",
            "rate_limit_per_minute": 60,
            "enabled": True
        })
        mock_manager.record_usage = AsyncMock()
        mock_manager_class.return_value = mock_manager

        # Mock query service
        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = []
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        client = TestClient(app)

        response = client.get(
            "/indicators",
            headers={"X-API-Key": "valid-key"}
        )

        assert response.status_code == 200
        assert "items" in response.json()

    @patch('api.services.query_service.CosmosClient')
    @patch('api.services.query_service.CacheService')
    @patch('api.middleware.auth.APIKeyManager')
    def test_invalid_api_key_denied(
        self,
        mock_manager_class,
        mock_cache_class,
        mock_cosmos_class
    ):
        """Should deny access with invalid API key"""
        # Mock invalid API key
        mock_manager = Mock()
        mock_manager.validate_api_key = AsyncMock(return_value=None)
        mock_manager_class.return_value = mock_manager

        client = TestClient(app)

        response = client.get(
            "/indicators",
            headers={"X-API-Key": "invalid-key"}
        )

        assert response.status_code == 403
        assert "Invalid API key" in response.json()["error"]


@pytest.mark.integration
class TestIndicatorsEndpoints:
    """Test indicators endpoints"""

    @patch('api.routers.indicators.query_service')
    @patch('api.middleware.auth.APIKeyManager')
    def test_query_indicators_with_filters(
        self,
        mock_manager_class,
        mock_query_service
    ):
        """Should query indicators with filters"""
        self._setup_valid_auth(mock_manager_class)

        # Mock query service response
        mock_query_service.query_indicators = AsyncMock(return_value={
            "items": [
                {
                    "id": "1",
                    "indicator_value": "evil.com",
                    "indicator_type": "domain",
                    "confidence_score": 90,
                    "source_count": 2,
                    "sources": [],
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z"
                }
            ],
            "continuation_token": None
        })

        client = TestClient(app)

        response = client.get(
            "/indicators?indicator_type=domain&confidence_min=80",
            headers={"X-API-Key": "valid-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["indicator_value"] == "evil.com"

    @patch('api.routers.indicators.query_service')
    @patch('api.middleware.auth.APIKeyManager')
    def test_search_indicators(
        self,
        mock_manager_class,
        mock_query_service
    ):
        """Should search indicators"""
        self._setup_valid_auth(mock_manager_class)

        mock_query_service.search_indicators = AsyncMock(return_value={
            "items": [
                {
                    "id": "1",
                    "indicator_value": "evil.com",
                    "indicator_type": "domain",
                    "confidence_score": 90,
                    "source_count": 1,
                    "sources": [],
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z"
                }
            ]
        })

        client = TestClient(app)

        response = client.get(
            "/indicators/search?q=evil",
            headers={"X-API-Key": "valid-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 1

    @patch('api.services.query_service.CosmosClient')
    @patch('api.services.query_service.CacheService')
    @patch('api.middleware.auth.APIKeyManager')
    def test_get_indicator_by_id(
        self,
        mock_manager_class,
        mock_cache_class,
        mock_cosmos_class
    ):
        """Should get indicator by ID"""
        self._setup_valid_auth(mock_manager_class)

        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = [{
            "id": "test-id",
            "indicator_value": "test.com",
            "indicator_type": "domain",
            "confidence_score": 85,
            "source_count": 1,
            "sources": [],
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        client = TestClient(app)

        response = client.get(
            "/indicators/test-id",
            headers={"X-API-Key": "valid-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "test-id"
        assert data["indicator_value"] == "test.com"

    @patch('api.services.query_service.CosmosClient')
    @patch('api.services.query_service.CacheService')
    @patch('api.middleware.auth.APIKeyManager')
    def test_get_nonexistent_indicator_404(
        self,
        mock_manager_class,
        mock_cache_class,
        mock_cosmos_class
    ):
        """Should return 404 for nonexistent indicator"""
        self._setup_valid_auth(mock_manager_class)

        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = []
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        client = TestClient(app)

        response = client.get(
            "/indicators/nonexistent",
            headers={"X-API-Key": "valid-key"}
        )

        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    def _setup_valid_auth(self, mock_manager_class):
        """Helper to setup valid authentication"""
        mock_manager = Mock()
        mock_manager.validate_api_key = AsyncMock(return_value={
            "api_key": "valid-key",
            "tier": "standard",
            "rate_limit_per_minute": 60,
            "enabled": True
        })
        mock_manager.record_usage = AsyncMock()
        mock_manager_class.return_value = mock_manager


@pytest.mark.integration
class TestRelationshipsEndpoints:
    """Test relationships endpoints"""

    @patch('api.services.query_service.CosmosClient')
    @patch('api.services.query_service.CacheService')
    @patch('api.middleware.auth.APIKeyManager')
    def test_query_relationships(
        self,
        mock_manager_class,
        mock_cache_class,
        mock_cosmos_class
    ):
        """Should query relationships"""
        self._setup_valid_auth(mock_manager_class)

        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = [
            {
                "id": "rel1",
                "source_id": "evil.com",
                "target_id": "1.2.3.4",
                "relationship_type": "resolves_to",
                "confidence": 0.95,
                "detected_at": "2024-01-01T00:00:00Z"
            }
        ]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        client = TestClient(app)

        response = client.get(
            "/relationships?indicator_id=evil.com",
            headers={"X-API-Key": "valid-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["relationship_type"] == "resolves_to"

    def _setup_valid_auth(self, mock_manager_class):
        """Helper to setup valid authentication"""
        mock_manager = Mock()
        mock_manager.validate_api_key = AsyncMock(return_value={
            "api_key": "valid-key",
            "tier": "standard",
            "rate_limit_per_minute": 60,
            "enabled": True
        })
        mock_manager.record_usage = AsyncMock()
        mock_manager_class.return_value = mock_manager


@pytest.mark.integration
class TestStatisticsEndpoints:
    """Test statistics endpoints"""

    @patch('api.services.query_service.CosmosClient')
    @patch('api.services.query_service.CacheService')
    @patch('api.middleware.auth.APIKeyManager')
    def test_get_statistics(
        self,
        mock_manager_class,
        mock_cache_class,
        mock_cosmos_class
    ):
        """Should return statistics"""
        self._setup_valid_auth(mock_manager_class)

        mock_cosmos = Mock()
        mock_cosmos.query_items.side_effect = [
            [1000],  # Total
            [500],   # domain
            [300],   # IPv4
            [100],   # url
            [100]    # hash
        ]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        client = TestClient(app)

        response = client.get(
            "/stats",
            headers={"X-API-Key": "valid-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total_indicators"] == 1000
        assert data["by_type"]["domain"] == 500

    def _setup_valid_auth(self, mock_manager_class):
        """Helper to setup valid authentication"""
        mock_manager = Mock()
        mock_manager.validate_api_key = AsyncMock(return_value={
            "api_key": "valid-key",
            "tier": "standard",
            "rate_limit_per_minute": 60,
            "enabled": True
        })
        mock_manager.record_usage = AsyncMock()
        mock_manager_class.return_value = mock_manager
