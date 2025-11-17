"""
Tests for Query Service

Following TDD - Tests written FIRST
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch

from api.services.query_service import QueryService


@pytest.mark.unit
class TestQueryIndicators:
    """Test querying indicators"""

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_query_indicators_returns_results(self, mock_cosmos_class, mock_cache_class):
        """Should return indicators from Cosmos DB"""
        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = [
            {"id": "1", "indicator_value": "evil.com", "indicator_type": "domain"},
            {"id": "2", "indicator_value": "1.2.3.4", "indicator_type": "IPv4"}
        ]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None  # Cache miss
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        results = await service.query_indicators()

        assert len(results["items"]) == 2
        assert results["items"][0]["indicator_value"] == "evil.com"
        assert results["items"][1]["indicator_type"] == "IPv4"

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_query_indicators_with_filter(self, mock_cosmos_class, mock_cache_class):
        """Should filter indicators by type"""
        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = [
            {"id": "1", "indicator_value": "evil.com", "indicator_type": "domain"}
        ]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        results = await service.query_indicators(indicator_type="domain")

        # Verify parameterized query was used
        call_args = mock_cosmos.query_items.call_args
        query = call_args[0][1]
        parameters = call_args[0][2]

        assert "WHERE" in query
        assert "@indicator_type" in query
        assert parameters[0]["name"] == "@indicator_type"
        assert parameters[0]["value"] == "domain"

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_query_indicators_with_pagination(self, mock_cosmos_class, mock_cache_class):
        """Should support pagination with continuation token"""
        mock_cosmos = Mock()
        mock_cosmos.query_items_with_continuation.return_value = (
            [{"id": "1", "indicator_value": "test.com"}],
            "continuation_token_abc123"
        )
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        results = await service.query_indicators(page_size=10)

        assert results["continuation_token"] == "continuation_token_abc123"
        assert len(results["items"]) == 1

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_query_indicators_uses_cache(self, mock_cosmos_class, mock_cache_class):
        """Should use cached results when available"""
        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        cached_data = {
            "items": [{"id": "1", "indicator_value": "cached.com"}],
            "continuation_token": None
        }
        mock_cache = AsyncMock()
        mock_cache.get.return_value = cached_data
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        results = await service.query_indicators()

        assert results == cached_data
        # Should not query Cosmos if cache hit
        mock_cosmos.query_items.assert_not_called()


@pytest.mark.unit
class TestQueryRelationships:
    """Test querying relationships"""

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_query_relationships_for_indicator(self, mock_cosmos_class, mock_cache_class):
        """Should return relationships for a specific indicator"""
        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = [
            {
                "id": "rel1",
                "source_id": "evil.com",
                "target_id": "malware.exe",
                "relationship_type": "downloads"
            }
        ]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        results = await service.query_relationships(indicator_id="evil.com")

        assert len(results["items"]) == 1
        assert results["items"][0]["relationship_type"] == "downloads"

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_query_relationships_by_type(self, mock_cosmos_class, mock_cache_class):
        """Should filter relationships by type"""
        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = [
            {"id": "rel1", "relationship_type": "resolves_to"}
        ]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        results = await service.query_relationships(relationship_type="resolves_to")

        # Verify parameterized query
        call_args = mock_cosmos.query_items.call_args
        parameters = call_args[0][2]
        assert any(p["name"] == "@relationship_type" for p in parameters)


@pytest.mark.unit
class TestGetStatistics:
    """Test statistics queries"""

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_get_statistics_returns_counts(self, mock_cosmos_class, mock_cache_class):
        """Should return indicator counts by type"""
        mock_cosmos = Mock()
        # Mock COUNT queries (total + 4 types: domain, IPv4, url, hash)
        mock_cosmos.query_items.side_effect = [
            [150],  # Total indicators (Cosmos returns scalar for VALUE COUNT)
            [50],   # Domains
            [30],   # IPv4
            [70],   # URLs
            [0]     # Hashes
        ]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        stats = await service.get_statistics()

        assert stats["total_indicators"] == 150
        assert stats["by_type"]["domain"] == 50
        assert stats["by_type"]["IPv4"] == 30
        assert stats["by_type"]["url"] == 70

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_get_statistics_caches_results(self, mock_cosmos_class, mock_cache_class):
        """Should cache statistics results"""
        mock_cosmos = Mock()
        mock_cosmos.query_items.side_effect = [
            [100],  # Total
            [50],   # domain
            [25],   # IPv4
            [25],   # url
            [0]     # hash
        ]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache.set = AsyncMock()
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        await service.get_statistics()

        # Verify cache was set
        mock_cache.set.assert_called_once()
        call_args = mock_cache.set.call_args[0]
        assert "stats" in call_args[0]  # Cache key


@pytest.mark.unit
class TestGetIndicatorById:
    """Test getting specific indicator"""

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_get_indicator_by_id_returns_indicator(self, mock_cosmos_class, mock_cache_class):
        """Should return indicator by ID"""
        mock_cosmos = Mock()
        mock_cosmos.get_item.return_value = {
            "id": "test-id",
            "indicator_value": "test.com",
            "indicator_type": "domain"
        }
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        result = await service.get_indicator_by_id("test-id")

        assert result["id"] == "test-id"
        assert result["indicator_value"] == "test.com"

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_get_indicator_by_id_returns_none_if_not_found(self, mock_cosmos_class, mock_cache_class):
        """Should return None for nonexistent indicator"""
        mock_cosmos = Mock()
        mock_cosmos.get_item.return_value = None
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        result = await service.get_indicator_by_id("nonexistent")

        assert result is None

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_get_indicator_by_id_uses_cache(self, mock_cosmos_class, mock_cache_class):
        """Should use cached indicator if available"""
        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        cached_indicator = {"id": "cached-id", "indicator_value": "cached.com"}
        mock_cache = AsyncMock()
        mock_cache.get.return_value = cached_indicator
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        result = await service.get_indicator_by_id("cached-id")

        assert result == cached_indicator
        mock_cosmos.get_item.assert_not_called()


@pytest.mark.unit
class TestSearchIndicators:
    """Test searching indicators"""

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_search_indicators_by_value(self, mock_cosmos_class, mock_cache_class):
        """Should search indicators by value pattern"""
        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = [
            {"id": "1", "indicator_value": "evil.com"},
            {"id": "2", "indicator_value": "evil.net"}
        ]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        results = await service.search_indicators(search_term="evil")

        assert len(results["items"]) == 2
        # Verify query uses LIKE or CONTAINS
        call_args = mock_cosmos.query_items.call_args
        query = call_args[0][1]
        assert "CONTAINS" in query.upper() or "LIKE" in query.upper()

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_search_indicators_prevents_injection(self, mock_cosmos_class, mock_cache_class):
        """Should use parameterized queries to prevent injection"""
        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = []
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        # Try SQL injection
        await service.search_indicators(search_term="'; DROP TABLE indicators--")

        # Verify parameterized query was used
        call_args = mock_cosmos.query_items.call_args
        parameters = call_args[0][2]
        assert len(parameters) > 0
        assert parameters[0]["name"].startswith("@")


@pytest.mark.unit
class TestQueryServiceEdgeCases:
    """Test edge cases and error handling"""

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_handles_cosmos_errors(self, mock_cosmos_class, mock_cache_class):
        """Should handle Cosmos DB errors gracefully"""
        mock_cosmos = Mock()
        mock_cosmos.query_items.side_effect = Exception("Cosmos error")
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.return_value = None
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        results = await service.query_indicators()

        # Should return empty results instead of crashing
        assert results["items"] == []

    @patch('api.services.query_service.CacheService')
    @patch('api.services.query_service.CosmosClient')
    async def test_handles_cache_failures_gracefully(self, mock_cosmos_class, mock_cache_class):
        """Should continue working if cache fails"""
        mock_cosmos = Mock()
        mock_cosmos.query_items.return_value = [{"id": "1"}]
        mock_cosmos_class.return_value = mock_cosmos

        mock_cache = AsyncMock()
        mock_cache.get.side_effect = Exception("Cache error")
        mock_cache_class.return_value = mock_cache

        service = QueryService()
        service.cosmos_client = mock_cosmos
        service.cache = mock_cache

        # Should still query Cosmos even if cache fails
        results = await service.query_indicators()

        assert len(results["items"]) == 1
