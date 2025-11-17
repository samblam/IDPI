"""
Tests for CosmosClient with security best practices

Following TDD - tests written FIRST
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
import hashlib

# Will implement after tests
from storage.cosmos_client import CosmosClient


@pytest.mark.unit
class TestCosmosClientInitialization:
    """Test Cosmos client initialization"""

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_initialization_with_env_vars(self, mock_init):
        """Should initialize from environment variables"""
        with patch.dict('os.environ', {
            'COSMOS_ENDPOINT': 'https://test.documents.azure.com:443/',
            'COSMOS_KEY': 'test-key-12345'
        }):
            client = CosmosClient()
            assert client.endpoint == 'https://test.documents.azure.com:443/'
            assert client.database_name == 'threatstream'

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_initialization_with_params(self, mock_init):
        """Should allow custom endpoint and key"""
        client = CosmosClient(
            endpoint='https://custom.documents.azure.com:443/',
            key='custom-key'
        )
        assert client.endpoint == 'https://custom.documents.azure.com:443/'


@pytest.mark.unit
class TestCosmosClientPartitionKey:
    """Test partition key strategy"""

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_generate_partition_key_distribution(self, mock_init):
        """Should generate hash-based partition keys for even distribution"""
        client = CosmosClient()

        # Test with same indicator type but different values
        key1 = client._generate_partition_key("1.2.3.4", "IPv4")
        key2 = client._generate_partition_key("5.6.7.8", "IPv4")

        # Should be different (hash-based)
        assert key1 != key2

        # Should follow format: type_hash
        assert key1.startswith("IPv4_")
        assert len(key1.split('_')[1]) == 2  # 2-char hash prefix

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_generate_partition_key_consistent(self, mock_init):
        """Should generate same key for same input"""
        client = CosmosClient()

        key1 = client._generate_partition_key("1.2.3.4", "IPv4")
        key2 = client._generate_partition_key("1.2.3.4", "IPv4")

        assert key1 == key2  # Deterministic

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_partition_key_uses_md5_hash(self, mock_init):
        """Should use MD5 hash for partition distribution"""
        client = CosmosClient()

        indicator_value = "test.malicious.com"
        expected_hash = hashlib.md5(indicator_value.encode()).hexdigest()[:2]
        expected_key = f"domain_{expected_hash}"

        key = client._generate_partition_key(indicator_value, "domain")
        assert key == expected_key


@pytest.mark.unit
class TestCosmosClientUpsertItem:
    """Test secure upsert operations"""

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_upsert_item_sets_partition_key(self, mock_init):
        """Should set partition_key on item"""
        mock_container = MagicMock()
        mock_database = MagicMock()
        mock_database.get_container_client.return_value = mock_container

        client = CosmosClient()
        client.database = mock_database

        item = {
            "source": "otx",
            "indicator_value": "1.2.3.4",
            "indicator_type": "IPv4"
        }

        client.upsert_item("test_container", item)

        # Should have added partition_key
        assert "partition_key" in item
        assert item["partition_key"].startswith("IPv4_")

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_upsert_item_generates_deterministic_id(self, mock_init):
        """Should generate consistent ID from source + indicator"""
        mock_container = MagicMock()
        mock_database = MagicMock()
        mock_database.get_container_client.return_value = mock_container

        client = CosmosClient()
        client.database = mock_database

        item = {
            "source": "otx",
            "indicator_value": "1.2.3.4",
            "indicator_type": "IPv4"
        }

        client.upsert_item("test_container", item)

        # Should have ID
        assert "id" in item
        assert item["id"] == "otx_1.2.3.4"


@pytest.mark.unit
class TestCosmosClientQueryItems:
    """Test parameterized query operations (NO SQL INJECTION)"""

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_query_items_uses_parameters(self, mock_init):
        """Should use parameterized queries"""
        mock_container = MagicMock()
        mock_database = MagicMock()
        mock_database.get_container_client.return_value = mock_container
        mock_container.query_items.return_value = [{"id": "1"}]

        client = CosmosClient()
        client.database = mock_database

        query = "SELECT * FROM c WHERE c.indicator_value = @value"
        parameters = [{"name": "@value", "value": "1.2.3.4"}]

        client.query_items("test_container", query, parameters)

        # Verify parameterized query was used
        mock_container.query_items.assert_called_once()
        call_kwargs = mock_container.query_items.call_args.kwargs
        assert call_kwargs["query"] == query
        assert call_kwargs["parameters"] == parameters
        assert call_kwargs["enable_cross_partition_query"] is True

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_query_items_returns_list(self, mock_init):
        """Should return list of items"""
        mock_container = MagicMock()
        mock_database = MagicMock()
        mock_database.get_container_client.return_value = mock_container
        mock_container.query_items.return_value = iter([{"id": "1"}, {"id": "2"}])

        client = CosmosClient()
        client.database = mock_database

        results = client.query_items("test", "SELECT * FROM c")

        assert isinstance(results, list)
        assert len(results) == 2


@pytest.mark.unit
class TestCosmosClientGetItemById:
    """Test get item by ID (most efficient query)"""

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_get_item_by_id_uses_point_read(self, mock_init):
        """Should use efficient point read"""
        mock_container = MagicMock()
        mock_database = MagicMock()
        mock_database.get_container_client.return_value = mock_container
        mock_container.read_item.return_value = {"id": "test_id"}

        client = CosmosClient()
        client.database = mock_database

        result = client.get_item_by_id("container", "test_id", "partition_key_value")

        # Verify point read was used (most efficient)
        mock_container.read_item.assert_called_once_with(
            item="test_id",
            partition_key="partition_key_value"
        )
        assert result == {"id": "test_id"}

    @patch('storage.cosmos_client.CosmosClient._init_cosmos')
    def test_get_item_by_id_handles_not_found(self, mock_init):
        """Should return None if item not found"""
        mock_container = MagicMock()
        mock_database = MagicMock()
        mock_database.get_container_client.return_value = mock_container
        mock_container.read_item.side_effect = Exception("Not found")

        client = CosmosClient()
        client.database = mock_database

        result = client.get_item_by_id("container", "nonexistent", "key")

        assert result is None
