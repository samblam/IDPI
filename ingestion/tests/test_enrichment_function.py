"""
Tests for Enrichment Function

Following TDD - Tests written FIRST
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone, timedelta

from functions.enrichment_function import process_enrichment, is_recently_enriched


@pytest.mark.unit
class TestIsRecentlyEnriched:
    """Test checking if indicator was recently enriched"""

    def test_recently_enriched_returns_true(self):
        """Should return True if enriched in last 24 hours"""
        recent_time = datetime.now(timezone.utc) - timedelta(hours=12)
        indicator = {
            "enriched_at": recent_time.isoformat().replace('+00:00', 'Z')
        }

        assert is_recently_enriched(indicator) is True

    def test_not_recently_enriched_returns_false(self):
        """Should return False if enriched over 24 hours ago"""
        old_time = datetime.now(timezone.utc) - timedelta(hours=48)
        indicator = {
            "enriched_at": old_time.isoformat().replace('+00:00', 'Z')
        }

        assert is_recently_enriched(indicator) is False

    def test_no_enriched_at_returns_false(self):
        """Should return False if indicator has no enriched_at field"""
        indicator = {}
        assert is_recently_enriched(indicator) is False

    def test_exactly_24_hours_returns_false(self):
        """Should return False if exactly 24 hours (boundary case)"""
        exact_time = datetime.now(timezone.utc) - timedelta(hours=24, seconds=1)
        indicator = {
            "enriched_at": exact_time.isoformat().replace('+00:00', 'Z')
        }

        assert is_recently_enriched(indicator) is False


@pytest.mark.unit
@pytest.mark.asyncio
class TestProcessEnrichment:
    """Test enrichment processing function"""

    @patch('functions.enrichment_function.CosmosClient')
    @patch('functions.enrichment_function.ThreatEnrichmentEngine')
    async def test_process_single_high_confidence_indicator(self, mock_engine_class, mock_cosmos_class):
        """Should process single high-confidence indicator"""
        # Setup mocks
        mock_engine = AsyncMock()
        mock_engine_class.return_value = mock_engine

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Mock enrichment result
        enriched = {
            "indicator_value": "evil.com",
            "confidence_score": 90,
            "enrichment": {
                "classification": "malware",
                "severity": "High",
                "mitre_ttps": ["T1566"],
                "recommended_actions": ["Block domain"]
            },
            "enriched_at": "2024-01-01T10:00:00Z"
        }
        mock_engine.enrich_indicator.return_value = enriched

        # Create mock document
        doc = {
            "indicator_value": "evil.com",
            "confidence_score": 90,
            "sources": []
        }

        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc]))

        # Process
        await process_enrichment(mock_doc_list)

        # Verify enrichment was called
        mock_engine.enrich_indicator.assert_called_once()

        # Verify upsert to enriched_indicators container
        mock_cosmos.upsert_item.assert_called_once_with(
            "enriched_indicators",
            enriched
        )

    @patch('functions.enrichment_function.CosmosClient')
    @patch('functions.enrichment_function.ThreatEnrichmentEngine')
    async def test_skips_low_confidence_indicators(self, mock_engine_class, mock_cosmos_class):
        """Should skip indicators with confidence < 75"""
        mock_engine = AsyncMock()
        mock_engine_class.return_value = mock_engine

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Low confidence document
        doc = {
            "indicator_value": "test.com",
            "confidence_score": 50,  # Below threshold
            "sources": []
        }

        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc]))

        # Process
        await process_enrichment(mock_doc_list)

        # Verify enrichment was NOT called
        mock_engine.enrich_indicator.assert_not_called()
        mock_cosmos.upsert_item.assert_not_called()

    @patch('functions.enrichment_function.CosmosClient')
    @patch('functions.enrichment_function.ThreatEnrichmentEngine')
    async def test_skips_recently_enriched_indicators(self, mock_engine_class, mock_cosmos_class):
        """Should skip indicators already enriched in last 24 hours"""
        mock_engine = AsyncMock()
        mock_engine_class.return_value = mock_engine

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Recently enriched document
        recent_time = datetime.now(timezone.utc) - timedelta(hours=12)
        doc = {
            "indicator_value": "evil.com",
            "confidence_score": 90,
            "enriched_at": recent_time.isoformat().replace('+00:00', 'Z'),
            "sources": []
        }

        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc]))

        # Process
        await process_enrichment(mock_doc_list)

        # Verify enrichment was NOT called
        mock_engine.enrich_indicator.assert_not_called()
        mock_cosmos.upsert_item.assert_not_called()

    @patch('functions.enrichment_function.CosmosClient')
    @patch('functions.enrichment_function.ThreatEnrichmentEngine')
    async def test_processes_multiple_indicators(self, mock_engine_class, mock_cosmos_class):
        """Should process multiple high-confidence indicators"""
        mock_engine = AsyncMock()
        mock_engine_class.return_value = mock_engine

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Mock different enrichment results
        enriched1 = {"indicator_value": "evil1.com", "enriched_at": "2024-01-01T10:00:00Z"}
        enriched2 = {"indicator_value": "evil2.com", "enriched_at": "2024-01-01T10:01:00Z"}

        mock_engine.enrich_indicator.side_effect = [enriched1, enriched2]

        # Multiple documents
        doc1 = {"indicator_value": "evil1.com", "confidence_score": 85, "sources": []}
        doc2 = {"indicator_value": "evil2.com", "confidence_score": 90, "sources": []}

        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc1, doc2]))

        # Process
        await process_enrichment(mock_doc_list)

        # Verify both were enriched
        assert mock_engine.enrich_indicator.call_count == 2
        assert mock_cosmos.upsert_item.call_count == 2

    @patch('functions.enrichment_function.CosmosClient')
    @patch('functions.enrichment_function.ThreatEnrichmentEngine')
    async def test_handles_enrichment_error_gracefully(self, mock_engine_class, mock_cosmos_class):
        """Should handle enrichment errors without crashing"""
        mock_engine = AsyncMock()
        mock_engine_class.return_value = mock_engine

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Mock enrichment to raise error
        mock_engine.enrich_indicator.side_effect = Exception("OpenAI API error")

        doc = {
            "indicator_value": "evil.com",
            "confidence_score": 90,
            "sources": []
        }

        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc]))

        # Should not crash
        await process_enrichment(mock_doc_list)

        # Verify upsert was NOT called
        mock_cosmos.upsert_item.assert_not_called()

    @patch('functions.enrichment_function.CosmosClient')
    @patch('functions.enrichment_function.ThreatEnrichmentEngine')
    async def test_handles_cosmos_error_gracefully(self, mock_engine_class, mock_cosmos_class):
        """Should handle Cosmos DB errors without crashing"""
        mock_engine = AsyncMock()
        mock_engine_class.return_value = mock_engine

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Mock successful enrichment
        enriched = {"indicator_value": "evil.com", "enriched_at": "2024-01-01T10:00:00Z"}
        mock_engine.enrich_indicator.return_value = enriched

        # Mock Cosmos error
        mock_cosmos.upsert_item.side_effect = Exception("Cosmos connection failed")

        doc = {
            "indicator_value": "evil.com",
            "confidence_score": 90,
            "sources": []
        }

        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc]))

        # Should not crash
        await process_enrichment(mock_doc_list)

        # Verify enrichment was attempted
        mock_engine.enrich_indicator.assert_called_once()

    @patch('functions.enrichment_function.CosmosClient')
    @patch('functions.enrichment_function.ThreatEnrichmentEngine')
    async def test_empty_document_list(self, mock_engine_class, mock_cosmos_class):
        """Should handle empty document list gracefully"""
        mock_engine = AsyncMock()
        mock_engine_class.return_value = mock_engine

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Empty document list
        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([]))
        mock_doc_list.__len__ = Mock(return_value=0)

        # Process
        await process_enrichment(mock_doc_list)

        # Verify nothing was called
        mock_engine.enrich_indicator.assert_not_called()
        mock_cosmos.upsert_item.assert_not_called()

    @patch('functions.enrichment_function.CosmosClient')
    @patch('functions.enrichment_function.ThreatEnrichmentEngine')
    async def test_mixed_confidence_indicators(self, mock_engine_class, mock_cosmos_class):
        """Should process only high-confidence indicators from mixed batch"""
        mock_engine = AsyncMock()
        mock_engine_class.return_value = mock_engine

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        enriched = {"indicator_value": "evil.com", "enriched_at": "2024-01-01T10:00:00Z"}
        mock_engine.enrich_indicator.return_value = enriched

        # Mixed confidence documents
        doc_high = {"indicator_value": "evil.com", "confidence_score": 85, "sources": []}
        doc_low1 = {"indicator_value": "test1.com", "confidence_score": 60, "sources": []}
        doc_low2 = {"indicator_value": "test2.com", "confidence_score": 40, "sources": []}
        doc_high2 = {"indicator_value": "bad.com", "confidence_score": 95, "sources": []}

        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc_high, doc_low1, doc_low2, doc_high2]))

        # Process
        await process_enrichment(mock_doc_list)

        # Verify only 2 high-confidence indicators were enriched
        assert mock_engine.enrich_indicator.call_count == 2
        assert mock_cosmos.upsert_item.call_count == 2

    @patch('functions.enrichment_function.CosmosClient')
    @patch('functions.enrichment_function.ThreatEnrichmentEngine')
    async def test_exact_threshold_confidence_is_processed(self, mock_engine_class, mock_cosmos_class):
        """Should process indicator with confidence exactly at threshold (75)"""
        mock_engine = AsyncMock()
        mock_engine_class.return_value = mock_engine

        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        enriched = {"indicator_value": "evil.com", "enriched_at": "2024-01-01T10:00:00Z"}
        mock_engine.enrich_indicator.return_value = enriched

        # Exactly at threshold
        doc = {
            "indicator_value": "evil.com",
            "confidence_score": 75,  # Exactly at threshold
            "sources": []
        }

        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc]))

        # Process
        await process_enrichment(mock_doc_list)

        # Verify enrichment WAS called (>= 75)
        mock_engine.enrich_indicator.assert_called_once()
        mock_cosmos.upsert_item.assert_called_once()
