"""
Tests for Normalization Change Feed Function

Following TDD - Tests written FIRST
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Note: We'll mock azure.functions since it may not be installed in test env
from functions.normalization_function import process_normalization


@pytest.mark.unit
class TestNormalizationChangeFunction:
    """Test Cosmos DB change feed normalization function"""

    @pytest.fixture
    def raw_otx_document(self):
        """Sample raw OTX indicator from change feed"""
        return {
            "id": "raw_otx_192.168.1.1",
            "source": "otx",
            "indicator_value": "192.168.1.1",
            "indicator_type": "IPv4",
            "ingested_at": "2024-01-01T10:00:00Z",
            "raw_metadata": {
                "pulse_id": "abc123",
                "pulse_name": "Malicious IPs",
                "tlp": "amber",
                "tags": ["malware", "botnet"],
                "description": "Known botnet C2 server"
            }
        }

    @pytest.fixture
    def raw_abuseipdb_document(self):
        """Sample raw AbuseIPDB indicator"""
        return {
            "id": "raw_abuseipdb_5.6.7.8",
            "source": "abuseipdb",
            "indicator_value": "5.6.7.8",
            "indicator_type": "IPv4",
            "ingested_at": "2024-01-01T11:00:00Z",
            "raw_metadata": {
                "abuse_confidence_score": 95,
                "total_reports": 42,
                "last_reported_at": "2024-01-01T10:30:00Z"
            }
        }

    @pytest.fixture
    def mock_documents(self, raw_otx_document, raw_abuseipdb_document):
        """Mock DocumentList from change feed"""
        # Create mock documents list
        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([
            raw_otx_document,
            raw_abuseipdb_document
        ]))
        mock_doc_list.__len__ = Mock(return_value=2)
        return mock_doc_list

    @patch('functions.normalization_function.CosmosClient')
    @patch('functions.normalization_function.IndicatorNormalizer')
    def test_process_single_document(self, mock_normalizer_class, mock_cosmos_class,
                                     raw_otx_document):
        """Should process single document from change feed"""
        # Setup mocks
        mock_normalizer = Mock()
        mock_normalizer_class.return_value = mock_normalizer

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Mock normalization result
        normalized = {
            "id": "norm_otx_192.168.1.1",
            "indicator_value": "192.168.1.1",
            "indicator_type": "IPv4",
            "confidence_score": 70,
            "first_seen": "2024-01-01T10:00:00Z",
            "last_seen": "2024-01-01T10:00:00Z",
            "sources": [{
                "name": "otx",
                "pulse_id": "abc123",
                "tags": ["malware", "botnet"]
            }],
            "normalized_at": "2024-01-01T10:05:00Z"
        }
        mock_normalizer.normalize.return_value = normalized

        # Create mock document list
        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([raw_otx_document]))

        # Process documents
        process_normalization(mock_doc_list)

        # Verify normalizer was called with raw document
        mock_normalizer.normalize.assert_called_once_with(raw_otx_document)

        # Verify upsert to normalized_indicators container
        mock_cosmos.upsert_item.assert_called_once_with(
            "normalized_indicators",
            normalized
        )

    @patch('functions.normalization_function.CosmosClient')
    @patch('functions.normalization_function.IndicatorNormalizer')
    def test_process_multiple_documents(self, mock_normalizer_class, mock_cosmos_class,
                                       mock_documents):
        """Should process multiple documents from change feed"""
        # Setup mocks
        mock_normalizer = Mock()
        mock_normalizer_class.return_value = mock_normalizer

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Mock normalization - return different results for each call
        normalized_results = [
            {"id": "norm_otx_192.168.1.1", "indicator_value": "192.168.1.1"},
            {"id": "norm_abuseipdb_5.6.7.8", "indicator_value": "5.6.7.8"}
        ]
        mock_normalizer.normalize.side_effect = normalized_results

        # Process documents
        process_normalization(mock_documents)

        # Verify normalizer was called twice
        assert mock_normalizer.normalize.call_count == 2

        # Verify upsert was called twice
        assert mock_cosmos.upsert_item.call_count == 2

    @patch('functions.normalization_function.CosmosClient')
    @patch('functions.normalization_function.IndicatorNormalizer')
    def test_handles_normalization_error_gracefully(self, mock_normalizer_class,
                                                    mock_cosmos_class, raw_otx_document):
        """Should handle normalization errors without crashing"""
        # Setup mocks
        mock_normalizer = Mock()
        mock_normalizer_class.return_value = mock_normalizer

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Mock normalization to raise error
        mock_normalizer.normalize.side_effect = ValueError("Unknown source")

        # Create mock document list
        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([raw_otx_document]))

        # Should not raise exception
        process_normalization(mock_doc_list)

        # Verify upsert was NOT called
        mock_cosmos.upsert_item.assert_not_called()

    @patch('functions.normalization_function.CosmosClient')
    @patch('functions.normalization_function.IndicatorNormalizer')
    def test_handles_cosmos_error_gracefully(self, mock_normalizer_class,
                                            mock_cosmos_class, raw_otx_document):
        """Should handle Cosmos DB errors without crashing"""
        # Setup mocks
        mock_normalizer = Mock()
        mock_normalizer_class.return_value = mock_normalizer

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Mock successful normalization
        normalized = {"id": "norm_otx_192.168.1.1", "indicator_value": "192.168.1.1"}
        mock_normalizer.normalize.return_value = normalized

        # Mock Cosmos upsert to raise error
        mock_cosmos.upsert_item.side_effect = Exception("Cosmos connection failed")

        # Create mock document list
        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([raw_otx_document]))

        # Should not raise exception
        process_normalization(mock_doc_list)

        # Verify upsert was attempted
        mock_cosmos.upsert_item.assert_called_once()

    @patch('functions.normalization_function.CosmosClient')
    @patch('functions.normalization_function.IndicatorNormalizer')
    def test_empty_document_list(self, mock_normalizer_class, mock_cosmos_class):
        """Should handle empty document list gracefully"""
        # Setup mocks
        mock_normalizer = Mock()
        mock_normalizer_class.return_value = mock_normalizer

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Create empty mock document list
        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([]))

        # Process empty list
        process_normalization(mock_doc_list)

        # Verify no operations were performed
        mock_normalizer.normalize.assert_not_called()
        mock_cosmos.upsert_item.assert_not_called()

    @patch('functions.normalization_function.CosmosClient')
    @patch('functions.normalization_function.IndicatorNormalizer')
    def test_partial_batch_failure(self, mock_normalizer_class, mock_cosmos_class):
        """Should continue processing even if one document fails"""
        # Setup mocks
        mock_normalizer = Mock()
        mock_normalizer_class.return_value = mock_normalizer

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Create documents
        doc1 = {"source": "otx", "indicator_value": "1.2.3.4"}
        doc2 = {"source": "invalid", "indicator_value": "5.6.7.8"}  # Will fail
        doc3 = {"source": "abuseipdb", "indicator_value": "9.10.11.12"}

        # Mock normalization - fail on second, succeed on others
        normalized1 = {"id": "norm_otx_1.2.3.4"}
        normalized3 = {"id": "norm_abuseipdb_9.10.11.12"}

        mock_normalizer.normalize.side_effect = [
            normalized1,
            ValueError("Unknown source"),  # Second one fails
            normalized3
        ]

        # Create mock document list
        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc1, doc2, doc3]))

        # Process documents
        process_normalization(mock_doc_list)

        # Verify normalizer was called 3 times (all attempted)
        assert mock_normalizer.normalize.call_count == 3

        # Verify upsert was called only twice (for successful ones)
        assert mock_cosmos.upsert_item.call_count == 2
        mock_cosmos.upsert_item.assert_any_call("normalized_indicators", normalized1)
        mock_cosmos.upsert_item.assert_any_call("normalized_indicators", normalized3)

    @patch('functions.normalization_function.CosmosClient')
    @patch('functions.normalization_function.IndicatorNormalizer')
    def test_stores_in_correct_container(self, mock_normalizer_class, mock_cosmos_class,
                                        raw_otx_document):
        """Should store normalized indicators in 'normalized_indicators' container"""
        # Setup mocks
        mock_normalizer = Mock()
        mock_normalizer_class.return_value = mock_normalizer

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        normalized = {"id": "norm_otx_192.168.1.1"}
        mock_normalizer.normalize.return_value = normalized

        # Create mock document list
        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([raw_otx_document]))

        # Process
        process_normalization(mock_doc_list)

        # Verify correct container name
        mock_cosmos.upsert_item.assert_called_once_with(
            "normalized_indicators",  # Must be this container
            normalized
        )


@pytest.mark.integration
class TestNormalizationFunctionIntegration:
    """Integration tests for normalization function"""

    @patch('functions.normalization_function.CosmosClient')
    def test_end_to_end_normalization(self, mock_cosmos_class):
        """Should normalize real indicator using actual IndicatorNormalizer"""
        # Use real normalizer (not mocked)
        from normalization.normalizer import IndicatorNormalizer

        # Setup mock Cosmos
        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Real raw document
        raw_doc = {
            "source": "otx",
            "indicator_value": "evil.com",
            "ingested_at": "2024-01-01T10:00:00Z",
            "raw_metadata": {
                "pulse_id": "test123",
                "pulse_name": "Test Pulse",
                "tlp": "red",
                "tags": ["phishing"],
                "description": "Test description"
            }
        }

        # Create mock document list
        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([raw_doc]))

        # Process with real normalizer
        with patch('functions.normalization_function.IndicatorNormalizer',
                   return_value=IndicatorNormalizer()):
            process_normalization(mock_doc_list)

        # Verify upsert was called
        assert mock_cosmos.upsert_item.call_count == 1

        # Get the normalized document that was stored
        stored_doc = mock_cosmos.upsert_item.call_args[0][1]

        # Verify normalization worked correctly
        assert stored_doc["id"] == "norm_otx_evil.com"
        assert stored_doc["indicator_value"] == "evil.com"
        assert stored_doc["indicator_type"] == "domain"
        assert stored_doc["confidence_score"] == 90  # TLP red = 90
        assert len(stored_doc["sources"]) == 1
        assert stored_doc["sources"][0]["name"] == "otx"
