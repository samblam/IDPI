"""
Query Service

Handles querying indicators, relationships, and statistics from Cosmos DB
"""
from typing import Dict, List, Optional, Tuple
import logging

from storage.cosmos_client import CosmosClient
from api.services.cache_service import CacheService


class QueryService:
    """
    Query service for indicators and relationships

    Provides optimized queries with caching and pagination support.
    """

    def __init__(self):
        """Initialize query service"""
        self.cosmos_client = CosmosClient()
        self.cache = CacheService()
        self.logger = logging.getLogger(self.__class__.__name__)

    async def query_indicators(
        self,
        indicator_type: Optional[str] = None,
        confidence_min: Optional[int] = None,
        page_size: Optional[int] = None,
        continuation_token: Optional[str] = None
    ) -> Dict:
        """
        Query indicators with optional filtering and pagination

        Args:
            indicator_type: Filter by indicator type
            confidence_min: Minimum confidence score
            page_size: Number of items per page
            continuation_token: Token for pagination

        Returns:
            Dictionary with items and optional continuation_token
        """
        try:
            # Build cache key
            cache_key = f"indicators:{indicator_type or 'all'}:{confidence_min or 0}"

            # Check cache (only for non-paginated queries)
            if not continuation_token:
                try:
                    cached = await self.cache.get(cache_key)
                    if cached:
                        self.logger.debug(f"Cache hit for {cache_key}")
                        return cached
                except Exception as cache_error:
                    self.logger.warning(f"Cache error, continuing with DB query: {cache_error}")

            # Build query
            query_parts = ["SELECT * FROM c"]
            parameters = []

            where_clauses = []
            if indicator_type:
                where_clauses.append("c.indicator_type = @indicator_type")
                parameters.append({"name": "@indicator_type", "value": indicator_type})

            if confidence_min is not None:
                where_clauses.append("c.confidence_score >= @confidence_min")
                parameters.append({"name": "@confidence_min", "value": confidence_min})

            if where_clauses:
                query_parts.append("WHERE " + " AND ".join(where_clauses))

            query = " ".join(query_parts)

            # Execute query
            if page_size:
                items, new_continuation = self.cosmos_client.query_items_with_continuation(
                    "enriched_indicators",
                    query,
                    parameters,
                    page_size,
                    continuation_token
                )
                result = {
                    "items": items,
                    "continuation_token": new_continuation
                }
            else:
                items = self.cosmos_client.query_items(
                    "enriched_indicators",
                    query,
                    parameters
                )
                result = {
                    "items": items,
                    "continuation_token": None
                }

            # Cache results (only for non-paginated queries)
            if not continuation_token and not page_size:
                await self.cache.set(cache_key, result, ttl=300)

            return result

        except Exception as e:
            self.logger.error(f"Error querying indicators: {e}", exc_info=True)
            return {"items": [], "continuation_token": None}

    async def query_relationships(
        self,
        indicator_id: Optional[str] = None,
        relationship_type: Optional[str] = None
    ) -> Dict:
        """
        Query relationships with optional filtering

        Args:
            indicator_id: Filter by source or target indicator
            relationship_type: Filter by relationship type

        Returns:
            Dictionary with relationship items
        """
        try:
            # Build cache key
            cache_key = f"relationships:{indicator_id or 'all'}:{relationship_type or 'all'}"

            # Check cache
            cached = await self.cache.get(cache_key)
            if cached:
                return cached

            # Build query
            query_parts = ["SELECT * FROM c"]
            parameters = []

            where_clauses = []
            if indicator_id:
                where_clauses.append("(c.source_id = @indicator_id OR c.target_id = @indicator_id)")
                parameters.append({"name": "@indicator_id", "value": indicator_id})

            if relationship_type:
                where_clauses.append("c.relationship_type = @relationship_type")
                parameters.append({"name": "@relationship_type", "value": relationship_type})

            if where_clauses:
                query_parts.append("WHERE " + " AND ".join(where_clauses))

            query = " ".join(query_parts)

            # Execute query
            items = self.cosmos_client.query_items(
                "indicator_relationships",
                query,
                parameters
            )

            result = {"items": items}

            # Cache results
            await self.cache.set(cache_key, result, ttl=300)

            return result

        except Exception as e:
            self.logger.error(f"Error querying relationships: {e}", exc_info=True)
            return {"items": []}

    def _extract_count_from_result(self, result: list) -> int:
        """
        Extract count value from Cosmos DB query result

        Handles both dictionary format ({"count": N}) and scalar format (N)

        Args:
            result: Query result list

        Returns:
            Count value or 0 if result is empty
        """
        if not result:
            return 0

        first_item = result[0]

        if isinstance(first_item, dict):
            return first_item.get("count", 0)
        else:
            return first_item

    async def get_statistics(self) -> Dict:
        """
        Get statistics about indicators

        Returns:
            Dictionary with indicator statistics
        """
        try:
            # Check cache
            cache_key = "stats:indicators"
            cached = await self.cache.get(cache_key)
            if cached:
                return cached

            # Get total count
            total_query = "SELECT VALUE COUNT(1) FROM c"
            total_result = self.cosmos_client.query_items(
                "enriched_indicators",
                total_query,
                []
            )
            total = self._extract_count_from_result(total_result)

            # Get counts by type
            by_type = {}
            for ioc_type in ["domain", "IPv4", "url", "hash"]:
                count_query = "SELECT VALUE COUNT(1) FROM c WHERE c.indicator_type = @type"
                count_result = self.cosmos_client.query_items(
                    "enriched_indicators",
                    count_query,
                    [{"name": "@type", "value": ioc_type}]
                )
                count = self._extract_count_from_result(count_result)
                by_type[ioc_type] = count

            stats = {
                "total_indicators": total,
                "by_type": by_type
            }

            # Cache for 5 minutes
            await self.cache.set(cache_key, stats, ttl=300)

            return stats

        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}", exc_info=True)
            return {"total_indicators": 0, "by_type": {}}

    async def get_indicator_by_id(self, indicator_id: str) -> Optional[Dict]:
        """
        Get indicator by ID

        Args:
            indicator_id: Indicator ID

        Returns:
            Indicator dictionary or None
        """
        try:
            # Check cache
            cache_key = f"indicator:{indicator_id}"
            cached = await self.cache.get(cache_key)
            if cached:
                return cached

            # Get from Cosmos
            indicator = self.cosmos_client.get_item("enriched_indicators", indicator_id)

            if indicator:
                # Cache for 10 minutes
                await self.cache.set(cache_key, indicator, ttl=600)

            return indicator

        except Exception as e:
            self.logger.error(f"Error getting indicator {indicator_id}: {e}", exc_info=True)
            return None

    async def search_indicators(
        self,
        search_term: str,
        page_size: Optional[int] = None
    ) -> Dict:
        """
        Search indicators by value

        Args:
            search_term: Search term
            page_size: Number of items per page

        Returns:
            Dictionary with search results
        """
        try:
            # Build parameterized query to prevent injection
            query = "SELECT * FROM c WHERE CONTAINS(LOWER(c.indicator_value), LOWER(@search_term))"
            parameters = [{"name": "@search_term", "value": search_term}]

            # Execute query
            items = self.cosmos_client.query_items(
                "enriched_indicators",
                query,
                parameters
            )

            return {"items": items}

        except Exception as e:
            self.logger.error(f"Error searching indicators: {e}", exc_info=True)
            return {"items": []}
