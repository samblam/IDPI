"""
Cache Service with Circuit Breaker Pattern

Provides resilient Redis caching with automatic failure recovery
"""
from typing import Any, Optional
from datetime import datetime
from enum import Enum
import json
import logging
import os

import redis


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, don't attempt calls
    HALF_OPEN = "half_open"  # Testing if service recovered


class CacheService:
    """
    Redis cache service with circuit breaker pattern

    Provides resilient caching that gracefully degrades when Redis
    is unavailable, preventing cascading failures.
    """

    def __init__(
        self,
        prefix: str = "idp:",
        default_ttl: int = 600,
        failure_threshold: int = 3,
        recovery_timeout: int = 30
    ):
        """
        Initialize cache service

        Args:
            prefix: Key prefix for all cache entries
            default_ttl: Default time-to-live in seconds
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
        """
        self.prefix = prefix
        self.default_ttl = default_ttl
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        # Circuit breaker state
        self.circuit_state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0

        # Initialize Redis client
        redis_host = os.getenv("REDIS_HOST", "localhost")
        redis_port = int(os.getenv("REDIS_PORT", "6379"))
        redis_password = os.getenv("REDIS_PASSWORD", None)

        try:
            self.redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                password=redis_password,
                decode_responses=False,
                socket_connect_timeout=2,
                socket_timeout=2
            )
        except Exception as e:
            self.logger = logging.getLogger(self.__class__.__name__)
            self.logger.error(f"Failed to initialize Redis client: {e}")
            self.circuit_state = CircuitState.OPEN

        self.logger = logging.getLogger(self.__class__.__name__)

    def _get_key(self, key: str) -> str:
        """Apply prefix to cache key"""
        return f"{self.prefix}{key}"

    def _should_attempt_call(self) -> bool:
        """Check if call should be attempted based on circuit state"""
        if self.circuit_state == CircuitState.CLOSED:
            return True

        if self.circuit_state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            time_since_failure = datetime.now().timestamp() - self.last_failure_time
            if time_since_failure >= self.recovery_timeout:
                self.logger.info("Circuit breaker: Transitioning to HALF_OPEN")
                self.circuit_state = CircuitState.HALF_OPEN
                return True
            return False

        # HALF_OPEN state - allow one test call
        return True

    def _record_success(self):
        """Record successful call"""
        if self.circuit_state == CircuitState.HALF_OPEN:
            self.logger.info("Circuit breaker: Closing circuit after successful call")
            self.circuit_state = CircuitState.CLOSED

        self.failure_count = 0

    def _record_failure(self):
        """Record failed call"""
        self.failure_count += 1
        self.last_failure_time = datetime.now().timestamp()

        if self.circuit_state == CircuitState.HALF_OPEN:
            self.logger.warning("Circuit breaker: Re-opening circuit after failed test")
            self.circuit_state = CircuitState.OPEN
        elif self.failure_count >= self.failure_threshold:
            self.logger.error(f"Circuit breaker: Opening circuit after {self.failure_count} failures")
            self.circuit_state = CircuitState.OPEN

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache

        Args:
            key: Cache key

        Returns:
            Cached value if present, None otherwise
        """
        if not self._should_attempt_call():
            self.logger.debug(f"Circuit OPEN: Skipping cache GET for {key}")
            return None

        try:
            prefixed_key = self._get_key(key)
            value = self.redis_client.get(prefixed_key)

            if value is None:
                self._record_success()
                return None

            # Deserialize JSON
            deserialized = json.loads(value.decode('utf-8'))
            self._record_success()
            return deserialized

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in cache for key {key}: {e}")
            self._record_success()  # Not a Redis failure
            return None

        except Exception as e:
            self.logger.error(f"Cache GET error for key {key}: {e}")
            self._record_failure()
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set value in cache

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if not specified)

        Returns:
            True if successful, False otherwise
        """
        if not self._should_attempt_call():
            self.logger.debug(f"Circuit OPEN: Skipping cache SET for {key}")
            return False

        try:
            prefixed_key = self._get_key(key)
            ttl = ttl or self.default_ttl

            # Serialize to JSON
            serialized = json.dumps(value)

            self.redis_client.setex(prefixed_key, ttl, serialized)
            self._record_success()
            return True

        except (TypeError, ValueError) as e:
            self.logger.error(f"Serialization error for key {key}: {e}")
            # Don't record as Redis failure
            return False

        except Exception as e:
            self.logger.error(f"Cache SET error for key {key}: {e}")
            self._record_failure()
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete value from cache

        Args:
            key: Cache key

        Returns:
            True if deleted, False otherwise
        """
        if not self._should_attempt_call():
            self.logger.debug(f"Circuit OPEN: Skipping cache DELETE for {key}")
            return False

        try:
            prefixed_key = self._get_key(key)
            self.redis_client.delete(prefixed_key)
            self._record_success()
            return True

        except Exception as e:
            self.logger.error(f"Cache DELETE error for key {key}: {e}")
            self._record_failure()
            return False
