"""
Tests for Deduplication Engine

Following TDD - Tests written FIRST
"""
import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from normalization.deduplicator import DeduplicationEngine, merge_duplicates, calculate_composite_score


@pytest.mark.unit
class TestCompositeScoreCalculation:
    """Test composite confidence score calculation"""

    def test_single_source_score_unchanged(self):
        """Should return score unchanged with single source"""
        scores = [75]
        result = calculate_composite_score(scores)
        assert result == 75

    def test_multiple_sources_boost_confidence(self):
        """Should boost confidence when multiple sources agree"""
        # Two sources with avg score 70 should boost by 10%
        scores = [70, 70]
        result = calculate_composite_score(scores)
        assert result == 77  # 70 * 1.1 = 77

    def test_three_sources_boost_more(self):
        """Should boost more with three sources"""
        scores = [60, 60, 60]
        result = calculate_composite_score(scores)
        assert result == 72  # 60 * 1.2 = 72

    def test_max_boost_capped_at_150_percent(self):
        """Should cap boost at 150% (max multiplier 1.5)"""
        # 10 sources would give 1.9x multiplier, but capped at 1.5x
        scores = [50] * 10
        result = calculate_composite_score(scores)
        assert result == 75  # 50 * 1.5 = 75

    def test_score_never_exceeds_100(self):
        """Should never return score > 100"""
        scores = [90, 90, 90, 90]
        result = calculate_composite_score(scores)
        assert result == 100  # Capped at 100

    def test_empty_scores_returns_zero(self):
        """Should return 0 for empty score list"""
        scores = []
        result = calculate_composite_score(scores)
        assert result == 0

    def test_mixed_scores_uses_average(self):
        """Should use average as base score"""
        scores = [50, 70, 90]
        # Average = 70, multiplier = 1.2, result = 84
        result = calculate_composite_score(scores)
        assert result == 84


@pytest.mark.unit
class TestMergeDuplicates:
    """Test merging of duplicate indicators"""

    @pytest.fixture
    def duplicate_indicators(self):
        """Sample duplicate indicators from different sources"""
        return [
            {
                "id": "norm_otx_192.168.1.1",
                "indicator_value": "192.168.1.1",
                "indicator_type": "IPv4",
                "confidence_score": 70,
                "first_seen": "2024-01-01T10:00:00Z",
                "last_seen": "2024-01-01T10:00:00Z",
                "sources": [{
                    "name": "otx",
                    "pulse_id": "abc123",
                    "tags": ["malware"]
                }]
            },
            {
                "id": "norm_abuseipdb_192.168.1.1",
                "indicator_value": "192.168.1.1",
                "indicator_type": "IPv4",
                "confidence_score": 95,
                "first_seen": "2024-01-01T12:00:00Z",
                "last_seen": "2024-01-01T12:00:00Z",
                "sources": [{
                    "name": "abuseipdb",
                    "total_reports": 50
                }]
            }
        ]

    def test_merge_combines_sources(self, duplicate_indicators):
        """Should combine sources from all duplicates"""
        merged = merge_duplicates(duplicate_indicators)

        assert len(merged["sources"]) == 2
        source_names = {s["name"] for s in merged["sources"]}
        assert source_names == {"otx", "abuseipdb"}

    def test_merge_calculates_composite_score(self, duplicate_indicators):
        """Should calculate composite confidence score"""
        merged = merge_duplicates(duplicate_indicators)

        # Scores: [70, 95], avg=82.5, multiplier=1.1, result=90.75 ≈ 90
        assert merged["confidence_score"] == 90

    def test_merge_uses_earliest_first_seen(self, duplicate_indicators):
        """Should use earliest first_seen timestamp"""
        merged = merge_duplicates(duplicate_indicators)

        assert merged["first_seen"] == "2024-01-01T10:00:00Z"

    def test_merge_uses_latest_last_seen(self, duplicate_indicators):
        """Should use latest last_seen timestamp"""
        merged = merge_duplicates(duplicate_indicators)

        assert merged["last_seen"] == "2024-01-01T12:00:00Z"

    def test_merge_counts_unique_sources(self, duplicate_indicators):
        """Should count number of unique sources"""
        merged = merge_duplicates(duplicate_indicators)

        assert merged["source_count"] == 2

    def test_merge_generates_dedup_id(self, duplicate_indicators):
        """Should generate deduplicated ID"""
        merged = merge_duplicates(duplicate_indicators)

        assert merged["id"] == "dedup_192.168.1.1"
        assert merged["indicator_value"] == "192.168.1.1"

    def test_merge_with_same_source_multiple_times(self):
        """Should handle multiple reports from same source"""
        duplicates = [
            {
                "indicator_value": "evil.com",
                "confidence_score": 60,
                "first_seen": "2024-01-01T10:00:00Z",
                "last_seen": "2024-01-01T10:00:00Z",
                "sources": [{"name": "otx", "pulse_id": "123"}]
            },
            {
                "indicator_value": "evil.com",
                "confidence_score": 70,
                "first_seen": "2024-01-01T11:00:00Z",
                "last_seen": "2024-01-01T11:00:00Z",
                "sources": [{"name": "otx", "pulse_id": "456"}]
            }
        ]

        merged = merge_duplicates(duplicates)

        # Should have 2 source entries (different pulse IDs)
        assert len(merged["sources"]) == 2
        # But only 1 unique source name
        assert merged["source_count"] == 1


@pytest.mark.unit
class TestDeduplicationEngine:
    """Test deduplication engine"""

    def test_initialization(self):
        """Should initialize deduplication engine"""
        engine = DeduplicationEngine()
        assert engine is not None

    def test_group_by_indicator_value(self):
        """Should group indicators by value"""
        engine = DeduplicationEngine()

        indicators = [
            {"indicator_value": "1.2.3.4", "id": "norm_otx_1.2.3.4"},
            {"indicator_value": "1.2.3.4", "id": "norm_abuseipdb_1.2.3.4"},
            {"indicator_value": "5.6.7.8", "id": "norm_otx_5.6.7.8"}
        ]

        grouped = engine.group_by_value(indicators)

        assert len(grouped) == 2
        assert "1.2.3.4" in grouped
        assert "5.6.7.8" in grouped
        assert len(grouped["1.2.3.4"]) == 2
        assert len(grouped["5.6.7.8"]) == 1

    def test_deduplicate_single_indicator(self):
        """Should return indicator unchanged if no duplicates"""
        engine = DeduplicationEngine()

        indicator = {
            "id": "norm_otx_1.2.3.4",
            "indicator_value": "1.2.3.4",
            "confidence_score": 75,
            "first_seen": "2024-01-01T10:00:00Z",
            "last_seen": "2024-01-01T10:00:00Z",
            "sources": [{"name": "otx"}]
        }

        result = engine.deduplicate([indicator])

        assert len(result) == 1
        assert result[0]["id"] == "dedup_1.2.3.4"

    def test_deduplicate_multiple_indicators(self):
        """Should merge duplicates and return deduplicated set"""
        engine = DeduplicationEngine()

        indicators = [
            {
                "indicator_value": "1.2.3.4",
                "confidence_score": 70,
                "first_seen": "2024-01-01T10:00:00Z",
                "last_seen": "2024-01-01T10:00:00Z",
                "sources": [{"name": "otx"}]
            },
            {
                "indicator_value": "1.2.3.4",
                "confidence_score": 90,
                "first_seen": "2024-01-01T11:00:00Z",
                "last_seen": "2024-01-01T11:00:00Z",
                "sources": [{"name": "abuseipdb"}]
            },
            {
                "indicator_value": "5.6.7.8",
                "confidence_score": 60,
                "first_seen": "2024-01-01T12:00:00Z",
                "last_seen": "2024-01-01T12:00:00Z",
                "sources": [{"name": "urlhaus"}]
            }
        ]

        result = engine.deduplicate(indicators)

        # Should return 2 deduplicated indicators
        assert len(result) == 2

        # Check merged indicator
        merged_ip = [r for r in result if r["indicator_value"] == "1.2.3.4"][0]
        assert merged_ip["source_count"] == 2
        assert len(merged_ip["sources"]) == 2

        # Check non-duplicate indicator
        single_ip = [r for r in result if r["indicator_value"] == "5.6.7.8"][0]
        assert single_ip["source_count"] == 1

    @patch('storage.cosmos_client.CosmosClient')
    def test_deduplicate_from_cosmos(self, mock_cosmos_class):
        """Should query Cosmos DB and deduplicate results"""
        engine = DeduplicationEngine()

        # Setup mock
        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        mock_cosmos.query_items.return_value = [
            {
                "indicator_value": "1.2.3.4",
                "confidence_score": 70,
                "first_seen": "2024-01-01T10:00:00Z",
                "last_seen": "2024-01-01T10:00:00Z",
                "sources": [{"name": "otx"}]
            },
            {
                "indicator_value": "1.2.3.4",
                "confidence_score": 90,
                "first_seen": "2024-01-01T11:00:00Z",
                "last_seen": "2024-01-01T11:00:00Z",
                "sources": [{"name": "abuseipdb"}]
            }
        ]

        result = engine.deduplicate_from_cosmos(
            container="normalized_indicators",
            hours_lookback=24
        )

        # Should query with parameterized query
        mock_cosmos.query_items.assert_called_once()
        call_args = mock_cosmos.query_items.call_args

        assert "normalized_indicators" in call_args[0]
        assert "WHERE" in call_args[0][1]  # Query string
        assert "@cutoff_time" in call_args[0][1]

        # Should return deduplicated results
        assert len(result) == 1
        assert result[0]["indicator_value"] == "1.2.3.4"
        assert result[0]["source_count"] == 2


@pytest.mark.unit
class TestDeduplicationEdgeCases:
    """Test deduplication edge cases"""

    def test_empty_indicator_list(self):
        """Should handle empty indicator list"""
        engine = DeduplicationEngine()

        result = engine.deduplicate([])

        assert result == []

    def test_all_same_indicator_value(self):
        """Should merge all indicators with same value"""
        engine = DeduplicationEngine()

        indicators = [
            {
                "indicator_value": "1.2.3.4",
                "confidence_score": 70,
                "first_seen": f"2024-01-01T{i:02d}:00:00Z",
                "last_seen": f"2024-01-01T{i:02d}:00:00Z",
                "sources": [{"name": f"source_{i}"}]
            }
            for i in range(5)
        ]

        result = engine.deduplicate(indicators)

        assert len(result) == 1
        assert result[0]["source_count"] == 5
        assert len(result[0]["sources"]) == 5

    def test_preserves_all_source_metadata(self):
        """Should preserve metadata from all sources"""
        engine = DeduplicationEngine()

        indicators = [
            {
                "indicator_value": "evil.com",
                "confidence_score": 70,
                "first_seen": "2024-01-01T10:00:00Z",
                "last_seen": "2024-01-01T10:00:00Z",
                "sources": [{
                    "name": "otx",
                    "pulse_id": "123",
                    "tags": ["malware"]
                }]
            },
            {
                "indicator_value": "evil.com",
                "confidence_score": 85,
                "first_seen": "2024-01-01T11:00:00Z",
                "last_seen": "2024-01-01T11:00:00Z",
                "sources": [{
                    "name": "urlhaus",
                    "threat": "phishing",
                    "tags": ["phish"]
                }]
            }
        ]

        result = engine.deduplicate(indicators)
        sources = result[0]["sources"]

        # Check OTX metadata preserved
        otx_source = [s for s in sources if s["name"] == "otx"][0]
        assert otx_source["pulse_id"] == "123"
        assert "malware" in otx_source["tags"]

        # Check URLhaus metadata preserved
        urlhaus_source = [s for s in sources if s["name"] == "urlhaus"][0]
        assert urlhaus_source["threat"] == "phishing"
        assert "phish" in urlhaus_source["tags"]
