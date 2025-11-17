"""
Tests for Cache Service with Circuit Breaker

Following TDD - Tests written FIRST
"""
import pytest
from unittest.mock import Mock, patch
import json
from datetime import datetime

from api.services.cache_service import CacheService, CircuitState


@pytest.mark.unit
class TestCacheServiceBasicOperations:
    """Test basic cache operations"""

    @patch('api.services.cache_service.redis.Redis')
    async def test_get_cached_value_returns_data(self, mock_redis_class):
        """Should return cached data when present"""
        mock_client = Mock()
        mock_client.get.return_value = json.dumps({"test": "data"}).encode()
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        result = await cache.get("test_key")

        assert result == {"test": "data"}
        mock_client.get.assert_called_once_with("idp:test_key")

    @patch('api.services.cache_service.redis.Redis')
    async def test_get_missing_key_returns_none(self, mock_redis_class):
        """Should return None when key doesn't exist"""
        mock_client = Mock()
        mock_client.get.return_value = None
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        result = await cache.get("missing_key")

        assert result is None

    @patch('api.services.cache_service.redis.Redis')
    async def test_set_caches_value_with_ttl(self, mock_redis_class):
        """Should cache value with TTL"""
        mock_client = Mock()
        mock_client.setex.return_value = True
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        await cache.set("test_key", {"data": "value"}, ttl=300)

        # Verify setex was called with correct parameters
        mock_client.setex.assert_called_once()
        call_args = mock_client.setex.call_args[0]
        assert call_args[0] == "idp:test_key"
        assert call_args[1] == 300
        assert json.loads(call_args[2]) == {"data": "value"}

    @patch('api.services.cache_service.redis.Redis')
    async def test_delete_removes_key(self, mock_redis_class):
        """Should delete key from cache"""
        mock_client = Mock()
        mock_client.delete.return_value = 1
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        await cache.delete("test_key")

        mock_client.delete.assert_called_once_with("idp:test_key")

    @patch('api.services.cache_service.redis.Redis')
    async def test_set_default_ttl(self, mock_redis_class):
        """Should use default TTL when not specified"""
        mock_client = Mock()
        mock_client.setex.return_value = True
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        cache.default_ttl = 600
        await cache.set("test_key", {"data": "value"})

        # Should use default TTL
        call_args = mock_client.setex.call_args[0]
        assert call_args[1] == 600


@pytest.mark.unit
class TestCircuitBreaker:
    """Test circuit breaker pattern"""

    @patch('api.services.cache_service.redis.Redis')
    async def test_circuit_starts_closed(self, mock_redis_class):
        """Should start with circuit in CLOSED state"""
        cache = CacheService()
        assert cache.circuit_state == CircuitState.CLOSED

    @patch('api.services.cache_service.redis.Redis')
    async def test_circuit_opens_after_failures(self, mock_redis_class):
        """Should open circuit after failure threshold"""
        mock_client = Mock()
        mock_client.get.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        cache.failure_threshold = 3

        # Trigger failures
        for _ in range(3):
            await cache.get("test_key")

        assert cache.circuit_state == CircuitState.OPEN

    @patch('api.services.cache_service.redis.Redis')
    async def test_open_circuit_returns_none_immediately(self, mock_redis_class):
        """Should return None immediately when circuit is OPEN"""
        mock_client = Mock()
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        cache.circuit_state = CircuitState.OPEN
        cache.last_failure_time = datetime.now().timestamp()  # Recent failure

        result = await cache.get("test_key")

        assert result is None
        # Should not call Redis when circuit is open
        mock_client.get.assert_not_called()

    @patch('api.services.cache_service.redis.Redis')
    async def test_circuit_transitions_to_half_open(self, mock_redis_class):
        """Should transition from OPEN to HALF_OPEN after timeout and then to CLOSED on success"""
        mock_client = Mock()
        mock_client.get.return_value = json.dumps({"test": "data"}).encode()
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        cache.circuit_state = CircuitState.OPEN
        cache.recovery_timeout = 0  # Immediate recovery for testing
        cache.last_failure_time = datetime.now().timestamp() - 1  # Past timeout

        result = await cache.get("test_key")

        # After successful call from OPEN, circuit should be CLOSED (via HALF_OPEN)
        assert cache.circuit_state == CircuitState.CLOSED
        assert result == {"test": "data"}

    @patch('api.services.cache_service.redis.Redis')
    async def test_half_open_closes_on_success(self, mock_redis_class):
        """Should close circuit from HALF_OPEN on successful call"""
        mock_client = Mock()
        mock_client.get.return_value = json.dumps({"test": "data"}).encode()
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        cache.circuit_state = CircuitState.HALF_OPEN

        result = await cache.get("test_key")

        assert cache.circuit_state == CircuitState.CLOSED
        assert result == {"test": "data"}

    @patch('api.services.cache_service.redis.Redis')
    async def test_half_open_reopens_on_failure(self, mock_redis_class):
        """Should reopen circuit from HALF_OPEN on failure"""
        mock_client = Mock()
        mock_client.get.side_effect = Exception("Redis error")
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client
        cache.circuit_state = CircuitState.HALF_OPEN

        result = await cache.get("test_key")

        assert cache.circuit_state == CircuitState.OPEN
        assert result is None


@pytest.mark.unit
class TestCacheServiceEdgeCases:
    """Test edge cases and error handling"""

    @patch('api.services.cache_service.redis.Redis')
    async def test_handles_redis_connection_error(self, mock_redis_class):
        """Should handle Redis connection errors gracefully"""
        mock_client = Mock()
        mock_client.get.side_effect = ConnectionError("Cannot connect")
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client

        result = await cache.get("test_key")
        assert result is None

    @patch('api.services.cache_service.redis.Redis')
    async def test_handles_invalid_json_in_cache(self, mock_redis_class):
        """Should handle invalid JSON in cache gracefully"""
        mock_client = Mock()
        mock_client.get.return_value = b"invalid json"
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client

        result = await cache.get("test_key")
        assert result is None

    @patch('api.services.cache_service.redis.Redis')
    async def test_set_handles_serialization_error(self, mock_redis_class):
        """Should handle objects that can't be serialized"""
        mock_client = Mock()
        mock_redis_class.return_value = mock_client

        cache = CacheService()
        cache.redis_client = mock_client

        # Object with circular reference (can't be serialized)
        class CircularRef:
            def __init__(self):
                self.ref = self

        obj = CircularRef()
        await cache.set("test_key", obj)

        # Should not raise exception, just log error
        # Redis set should not be called due to serialization error


@pytest.mark.unit
class TestCachePrefixing:
    """Test cache key prefixing"""

    @patch('api.services.cache_service.redis.Redis')
    async def test_uses_prefix_for_keys(self, mock_redis_class):
        """Should prepend prefix to all cache keys"""
        mock_client = Mock()
        mock_client.get.return_value = None
        mock_redis_class.return_value = mock_client

        cache = CacheService(prefix="idp:")
        cache.redis_client = mock_client
        await cache.get("indicators")

        # Should call Redis with prefixed key
        mock_client.get.assert_called_once_with("idp:indicators")

    @patch('api.services.cache_service.redis.Redis')
    async def test_prefix_applied_to_set(self, mock_redis_class):
        """Should apply prefix when setting values"""
        mock_client = Mock()
        mock_client.setex.return_value = True
        mock_redis_class.return_value = mock_client

        cache = CacheService(prefix="idp:")
        cache.redis_client = mock_client
        await cache.set("test", {"data": "value"}, ttl=60)

        call_args = mock_client.setex.call_args[0]
        assert call_args[0] == "idp:test"

    @patch('api.services.cache_service.redis.Redis')
    async def test_prefix_applied_to_delete(self, mock_redis_class):
        """Should apply prefix when deleting keys"""
        mock_client = Mock()
        mock_client.delete.return_value = 1
        mock_redis_class.return_value = mock_client

        cache = CacheService(prefix="idp:")
        cache.redis_client = mock_client
        await cache.delete("test")

        mock_client.delete.assert_called_once_with("idp:test")


@pytest.mark.unit
class TestCircuitStateEnum:
    """Test CircuitState enumeration"""

    def test_circuit_state_enum_values(self):
        """Should have all circuit states"""
        assert hasattr(CircuitState, 'CLOSED')
        assert hasattr(CircuitState, 'OPEN')
        assert hasattr(CircuitState, 'HALF_OPEN')

    def test_circuit_state_string_values(self):
        """Should have correct string values"""
        assert CircuitState.CLOSED.value == "closed"
        assert CircuitState.OPEN.value == "open"
        assert CircuitState.HALF_OPEN.value == "half_open"


@pytest.mark.unit
class TestCacheServiceConfiguration:
    """Test cache service configuration"""

    @patch('api.services.cache_service.redis.Redis')
    def test_initialization_with_custom_config(self, mock_redis_class):
        """Should initialize with custom configuration"""
        cache = CacheService(
            prefix="custom:",
            default_ttl=1200,
            failure_threshold=5,
            recovery_timeout=60
        )

        assert cache.prefix == "custom:"
        assert cache.default_ttl == 1200
        assert cache.failure_threshold == 5
        assert cache.recovery_timeout == 60

    @patch('api.services.cache_service.redis.Redis')
    def test_initialization_with_defaults(self, mock_redis_class):
        """Should initialize with default values"""
        cache = CacheService()

        assert cache.prefix == "idp:"
        assert cache.default_ttl == 600
        assert cache.failure_threshold == 3
        assert cache.recovery_timeout == 30
