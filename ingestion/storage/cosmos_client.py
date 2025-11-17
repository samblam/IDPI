"""
Cosmos DB Client with Security Best Practices

Features:
- Parameterized queries (NO SQL injection)
- Hash-based partition keys (prevents hot partitions)
- Efficient point reads
- TTL support
"""
from typing import Dict, List, Optional
import os
import hashlib
import logging


class CosmosClient:
    """
    Wrapper for Cosmos DB operations with security best practices

    Uses parameterized queries to prevent SQL injection
    Uses hash-based partition keys to avoid hot partitions
    """

    def __init__(self, endpoint: Optional[str] = None, key: Optional[str] = None):
        """
        Initialize Cosmos DB client

        Args:
            endpoint: Cosmos DB endpoint URL (or from COSMOS_ENDPOINT env var)
            key: Cosmos DB key (or from COSMOS_KEY env var)
        """
        self.endpoint = endpoint or os.getenv('COSMOS_ENDPOINT')
        self.key = key or os.getenv('COSMOS_KEY')
        self.database_name = os.getenv('COSMOS_DATABASE', 'threatstream')

        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize Cosmos client (only if credentials provided)
        if self.endpoint and self.key:
            self._init_cosmos()
        else:
            self.logger.warning("Cosmos credentials not provided - client not initialized")
            self.client = None
            self.database = None

    def _init_cosmos(self):
        """Initialize Azure Cosmos client"""
        try:
            from azure.cosmos import CosmosClient as AzureCosmosClient

            self.client = AzureCosmosClient(self.endpoint, self.key)
            self.database = self.client.get_database_client(self.database_name)

            self.logger.info(f"Cosmos DB client initialized: {self.database_name}")
        except ImportError:
            self.logger.error("azure-cosmos not installed")
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize Cosmos client: {e}")
            raise

    def _generate_partition_key(self, indicator_value: str, indicator_type: str) -> str:
        """
        Generate partition key to avoid hot partitions

        Combines type with hash prefix to distribute load across 256 partitions per type

        Args:
            indicator_value: The indicator value
            indicator_type: Type of indicator

        Returns:
            Partition key in format: type_hashprefix (e.g., "IPv4_a3")
        """
        # Use first 2 chars of MD5 hash to create 256 partitions per type
        hash_prefix = hashlib.md5(indicator_value.encode()).hexdigest()[:2]
        return f"{indicator_type}_{hash_prefix}"

    def upsert_item(self, container_name: str, item: Dict) -> Dict:
        """
        Insert or update item in container

        Automatically sets:
        - id: Deterministic ID from source + indicator_value
        - partition_key: Hash-based for distribution

        Args:
            container_name: Name of Cosmos container
            item: Item dictionary to upsert

        Returns:
            Upserted item
        """
        if not self.database:
            raise RuntimeError("Cosmos client not initialized")

        container = self.database.get_container_client(container_name)

        # Generate deterministic ID
        if 'source' in item and 'indicator_value' in item:
            item["id"] = f"{item['source']}_{item['indicator_value']}"

        # Set partition key to avoid hot partitions
        if 'indicator_type' in item and 'indicator_value' in item:
            item["partition_key"] = self._generate_partition_key(
                item['indicator_value'],
                item['indicator_type']
            )

        return container.upsert_item(item)

    def query_items(
        self,
        container_name: str,
        query: str,
        parameters: Optional[List[Dict]] = None
    ) -> List[Dict]:
        """
        Query items with PARAMETERIZED queries (prevents SQL injection)

        ALWAYS use parameters, NEVER string interpolation

        Example:
            query = "SELECT * FROM c WHERE c.value = @value"
            parameters = [{"name": "@value", "value": user_input}]
            results = client.query_items("container", query, parameters)

        Args:
            container_name: Container to query
            query: SQL query with parameter placeholders (@param)
            parameters: List of parameter dictionaries

        Returns:
            List of matching items
        """
        if not self.database:
            raise RuntimeError("Cosmos client not initialized")

        container = self.database.get_container_client(container_name)

        items = container.query_items(
            query=query,
            parameters=parameters or [],
            enable_cross_partition_query=True
        )

        return list(items)

    def get_item(self, container_name: str, item_id: str) -> Optional[Dict]:
        """
        Get single item by ID (without partition key)

        Uses query since partition key is not known.
        Less efficient than get_item_by_id but more convenient.

        Args:
            container_name: Container name
            item_id: Item ID

        Returns:
            Item if found, None otherwise
        """
        if not self.database:
            raise RuntimeError("Cosmos client not initialized")

        try:
            query = "SELECT * FROM c WHERE c.id = @id"
            parameters = [{"name": "@id", "value": item_id}]
            results = self.query_items(container_name, query, parameters)
            return results[0] if results else None
        except Exception as e:
            self.logger.warning(f"Item not found: {e}")
            return None

    def get_item_by_id(
        self,
        container_name: str,
        item_id: str,
        partition_key: str
    ) -> Optional[Dict]:
        """
        Get single item by ID and partition key (most efficient)

        This is a point read - the most efficient Cosmos DB operation

        Args:
            container_name: Container name
            item_id: Item ID
            partition_key: Partition key value

        Returns:
            Item if found, None otherwise
        """
        if not self.database:
            raise RuntimeError("Cosmos client not initialized")

        try:
            container = self.database.get_container_client(container_name)
            return container.read_item(item=item_id, partition_key=partition_key)
        except Exception as e:
            self.logger.warning(f"Item not found: {e}")
            return None

    def query_items_with_continuation(
        self,
        container_name: str,
        query: str,
        parameters: Optional[List[Dict]] = None,
        page_size: int = 100,
        continuation_token: Optional[str] = None
    ) -> tuple[List[Dict], Optional[str]]:
        """
        Query items with pagination support

        Args:
            container_name: Container to query
            query: SQL query with parameter placeholders
            parameters: List of parameter dictionaries
            page_size: Number of items per page
            continuation_token: Continuation token from previous query

        Returns:
            Tuple of (items, continuation_token)
        """
        if not self.database:
            raise RuntimeError("Cosmos client not initialized")

        container = self.database.get_container_client(container_name)

        query_iterable = container.query_items(
            query=query,
            parameters=parameters or [],
            enable_cross_partition_query=True,
            max_item_count=page_size
        )

        # Get items and continuation token
        items = []
        response_headers = {}

        try:
            # Fetch one page
            for item in query_iterable.by_page(continuation_token):
                items.extend(list(item))
                response_headers = query_iterable.response_headers
                break  # Only get first page

            new_continuation = response_headers.get('x-ms-continuation')
            return items, new_continuation

        except Exception as e:
            self.logger.error(f"Error during paginated query: {e}")
            return items, None
