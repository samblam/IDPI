"""
Integration Tests for Full Normalization Pipeline

Tests the complete flow: Raw Indicator → Normalization → Relationship Detection
"""
import pytest

from normalization.normalizer import IndicatorNormalizer
from normalization.relationship_detector import RelationshipDetector
from normalization.deduplicator import DeduplicationEngine, merge_duplicates, calculate_composite_score


@pytest.mark.integration
class TestNormalizationPipeline:
    """Test complete normalization pipeline end-to-end"""

    @pytest.fixture
    def normalizer(self):
        """Real IndicatorNormalizer instance"""
        return IndicatorNormalizer()

    @pytest.fixture
    def relationship_detector(self):
        """Real RelationshipDetector instance"""
        return RelationshipDetector()

    @pytest.fixture
    def deduplicator(self):
        """Real DeduplicationEngine instance"""
        return DeduplicationEngine()

    def test_otx_ip_normalization_flow(self, normalizer, relationship_detector):
        """Test complete flow for OTX IPv4 indicator"""
        # Raw indicator from ingestion
        raw = {
            "source": "otx",
            "indicator_value": "192.168.1.1",
            "ingested_at": "2024-01-01T10:00:00Z",
            "raw_metadata": {
                "pulse_id": "abc123",
                "pulse_name": "Malware Campaign",
                "tlp": "red",
                "tags": ["malware", "c2"],
                "description": "Command and control server"
            }
        }

        # Step 1: Normalize
        normalized = normalizer.normalize(raw)

        # Verify normalization
        assert normalized["id"] == "norm_otx_192.168.1.1"
        assert normalized["indicator_value"] == "192.168.1.1"
        assert normalized["indicator_type"] == "IPv4"
        assert normalized["confidence_score"] == 90  # TLP red = 90
        assert len(normalized["sources"]) == 1
        assert normalized["sources"][0]["name"] == "otx"

        # Step 2: Detect relationships
        relationships = relationship_detector.detect_relationships(normalized)

        # IP alone has no structural relationships, but has campaign
        assert len(relationships) == 1
        assert relationships[0]["type"] == "part_of_campaign"
        assert relationships[0]["campaign_id"] == "abc123"
        assert relationships[0]["campaign_name"] == "Malware Campaign"

    def test_otx_url_normalization_with_relationships(self, normalizer, relationship_detector):
        """Test complete flow for URL indicator with relationship extraction"""
        # Raw URL indicator
        raw = {
            "source": "otx",
            "indicator_value": "https://evil.com/malware.exe",
            "ingested_at": "2024-01-01T10:00:00Z",
            "raw_metadata": {
                "pulse_id": "xyz789",
                "pulse_name": "Phishing Campaign",
                "tlp": "amber",
                "tags": ["phishing"],
                "description": "Phishing URL"
            }
        }

        # Step 1: Normalize
        normalized = normalizer.normalize(raw)

        # Verify normalization
        assert normalized["indicator_type"] == "URL"
        assert normalized["confidence_score"] == 70  # TLP amber = 70

        # Step 2: Detect relationships
        relationships = relationship_detector.detect_relationships(normalized)

        # Should have 2 relationships: URL→domain + campaign
        assert len(relationships) == 2

        # Check URL→domain relationship
        domain_rels = [r for r in relationships if r["type"] == "contains_domain"]
        assert len(domain_rels) == 1
        assert domain_rels[0]["target_value"] == "evil.com"
        assert domain_rels[0]["target_type"] == "domain"

        # Check campaign relationship
        campaign_rels = [r for r in relationships if r["type"] == "part_of_campaign"]
        assert len(campaign_rels) == 1
        assert campaign_rels[0]["campaign_id"] == "xyz789"

    def test_abuseipdb_normalization_flow(self, normalizer, relationship_detector):
        """Test complete flow for AbuseIPDB indicator"""
        raw = {
            "source": "abuseipdb",
            "indicator_value": "10.0.0.1",
            "ingested_at": "2024-01-01T11:00:00Z",
            "raw_metadata": {
                "abuse_confidence_score": 95,
                "total_reports": 42,
                "last_reported_at": "2024-01-01T10:30:00Z"
            }
        }

        # Normalize
        normalized = normalizer.normalize(raw)

        # Verify
        assert normalized["indicator_type"] == "IPv4"
        assert normalized["confidence_score"] == 95  # Uses abuse_confidence_score
        assert normalized["sources"][0]["name"] == "abuseipdb"
        assert normalized["sources"][0]["total_reports"] == 42

        # Relationships (IP alone, no campaigns)
        relationships = relationship_detector.detect_relationships(normalized)
        assert relationships == []

    def test_urlhaus_url_normalization(self, normalizer, relationship_detector):
        """Test URLhaus URL normalization and relationship extraction"""
        raw = {
            "source": "urlhaus",
            "indicator_value": "http://192.168.1.100/backdoor.exe",
            "ingested_at": "2024-01-01T12:00:00Z",
            "raw_metadata": {
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["backdoor", "trojan"]
            }
        }

        # Normalize
        normalized = normalizer.normalize(raw)

        # Verify
        assert normalized["indicator_type"] == "URL"
        assert normalized["confidence_score"] == 80  # URLhaus online = 80

        # Relationships (URL→IP, no campaigns from URLhaus)
        relationships = relationship_detector.detect_relationships(normalized)

        assert len(relationships) == 1
        assert relationships[0]["type"] == "contains_ip"
        assert relationships[0]["target_value"] == "192.168.1.100"
        assert relationships[0]["target_type"] == "IPv4"

    def test_subdomain_relationship_detection(self, normalizer, relationship_detector):
        """Test subdomain→parent domain relationship"""
        raw = {
            "source": "otx",
            "indicator_value": "malware.evil.com",
            "ingested_at": "2024-01-01T10:00:00Z",
            "raw_metadata": {
                "pulse_id": "test123",
                "tlp": "green",
                "tags": []
            }
        }

        # Normalize
        normalized = normalizer.normalize(raw)

        assert normalized["indicator_type"] == "domain"

        # Detect relationships
        relationships = relationship_detector.detect_relationships(normalized)

        # Should have subdomain + campaign relationships
        assert len(relationships) == 2

        # Check subdomain relationship
        subdomain_rels = [r for r in relationships if r["type"] == "subdomain_of"]
        assert len(subdomain_rels) == 1
        assert subdomain_rels[0]["target_value"] == "evil.com"

    def test_deduplication_after_normalization(self, normalizer, deduplicator):
        """Test deduplication of normalized indicators"""
        # Two raw indicators for same IP from different sources
        raw1 = {
            "source": "otx",
            "indicator_value": "1.2.3.4",
            "ingested_at": "2024-01-01T10:00:00Z",
            "raw_metadata": {
                "pulse_id": "pulse1",
                "tlp": "amber",
                "tags": ["malware"]
            }
        }

        raw2 = {
            "source": "abuseipdb",
            "indicator_value": "1.2.3.4",
            "ingested_at": "2024-01-01T11:00:00Z",
            "raw_metadata": {
                "abuse_confidence_score": 90,
                "total_reports": 30
            }
        }

        # Normalize both
        normalized1 = normalizer.normalize(raw1)
        normalized2 = normalizer.normalize(raw2)

        # Deduplicate
        deduplicated = deduplicator.deduplicate([normalized1, normalized2])

        # Should return single merged indicator
        assert len(deduplicated) == 1

        merged = deduplicated[0]
        assert merged["id"] == "dedup_1.2.3.4"
        assert merged["indicator_value"] == "1.2.3.4"
        assert merged["source_count"] == 2
        assert len(merged["sources"]) == 2

        # Check composite score (avg of 70 and 90 = 80, +10% for 2 sources = 88)
        assert merged["confidence_score"] == 88

        # Check timestamps (earliest first_seen, latest last_seen)
        assert merged["first_seen"] == "2024-01-01T10:00:00Z"
        assert merged["last_seen"] == "2024-01-01T11:00:00Z"

    def test_full_pipeline_with_multiple_indicators(self, normalizer, relationship_detector, deduplicator):
        """Test complete pipeline with multiple indicators and deduplication"""
        # Simulate batch of raw indicators
        raw_indicators = [
            # IP from OTX
            {
                "source": "otx",
                "indicator_value": "5.6.7.8",
                "ingested_at": "2024-01-01T10:00:00Z",
                "raw_metadata": {"pulse_id": "p1", "tlp": "red", "tags": []}
            },
            # Same IP from AbuseIPDB
            {
                "source": "abuseipdb",
                "indicator_value": "5.6.7.8",
                "ingested_at": "2024-01-01T10:30:00Z",
                "raw_metadata": {"abuse_confidence_score": 85, "total_reports": 20}
            },
            # URL with domain
            {
                "source": "otx",
                "indicator_value": "https://phishing.com/login",
                "ingested_at": "2024-01-01T11:00:00Z",
                "raw_metadata": {"pulse_id": "p2", "tlp": "amber", "tags": ["phishing"]}
            },
            # Different IP
            {
                "source": "urlhaus",
                "indicator_value": "http://9.10.11.12/malware",
                "ingested_at": "2024-01-01T12:00:00Z",
                "raw_metadata": {"url_status": "online", "threat": "malware"}
            }
        ]

        # Step 1: Normalize all
        normalized_indicators = []
        for raw in raw_indicators:
            normalized = normalizer.normalize(raw)
            normalized_indicators.append(normalized)

        assert len(normalized_indicators) == 4

        # Step 2: Deduplicate
        deduplicated = deduplicator.deduplicate(normalized_indicators)

        # Should have 3 unique indicators (5.6.7.8 merged, others unique)
        assert len(deduplicated) == 3

        # Find the merged IP
        merged_ip = [d for d in deduplicated if d["indicator_value"] == "5.6.7.8"][0]
        assert merged_ip["source_count"] == 2
        assert merged_ip["confidence_score"] == 96  # (90+85)/2 * 1.1 ≈ 96

        # Step 3: Detect relationships for all
        for indicator in deduplicated:
            relationships = relationship_detector.detect_relationships(indicator)

            if indicator["indicator_type"] == "URL":
                # URLs should have relationships
                assert len(relationships) > 0
            # IPs might or might not have relationships depending on campaign info

    def test_composite_score_calculation(self):
        """Test composite score calculation with multiple sources"""
        # Test various scenarios
        assert calculate_composite_score([]) == 0
        assert calculate_composite_score([80]) == 80  # Single source unchanged
        assert calculate_composite_score([70, 70]) == 77  # 70 * 1.1
        assert calculate_composite_score([60, 60, 60]) == 72  # 60 * 1.2
        assert calculate_composite_score([50, 50, 50, 50, 50, 50]) == 75  # 50 * 1.5 (capped)
        assert calculate_composite_score([95, 95]) == 100  # Capped at 100

    def test_merge_preserves_all_metadata(self):
        """Test that merging preserves all source metadata"""
        duplicates = [
            {
                "indicator_value": "evil.com",
                "confidence_score": 70,
                "first_seen": "2024-01-01T10:00:00Z",
                "last_seen": "2024-01-01T10:00:00Z",
                "sources": [{
                    "name": "otx",
                    "pulse_id": "123",
                    "tags": ["malware"],
                    "custom_field": "value1"
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
                    "url_status": "online",
                    "custom_field": "value2"
                }]
            }
        ]

        merged = merge_duplicates(duplicates)

        # Verify all metadata preserved
        assert len(merged["sources"]) == 2

        otx_source = [s for s in merged["sources"] if s["name"] == "otx"][0]
        assert otx_source["pulse_id"] == "123"
        assert otx_source["custom_field"] == "value1"

        urlhaus_source = [s for s in merged["sources"] if s["name"] == "urlhaus"][0]
        assert urlhaus_source["threat"] == "phishing"
        assert urlhaus_source["custom_field"] == "value2"


@pytest.mark.integration
class TestNormalizationErrorHandling:
    """Test error handling in normalization pipeline"""

    def test_invalid_source_raises_error(self):
        """Test that invalid source raises ValueError"""
        normalizer = IndicatorNormalizer()

        raw = {
            "source": "invalid_source",
            "indicator_value": "test"
        }

        with pytest.raises(ValueError, match="Unknown source"):
            normalizer.normalize(raw)

    def test_missing_required_fields_raises_error(self):
        """Test that missing required fields raises KeyError"""
        normalizer = IndicatorNormalizer()

        raw = {
            # Missing 'source' field
            "indicator_value": "test"
        }

        with pytest.raises(KeyError):
            normalizer.normalize(raw)

    def test_deduplication_handles_empty_list(self):
        """Test that deduplication handles empty list gracefully"""
        deduplicator = DeduplicationEngine()

        result = deduplicator.deduplicate([])

        assert result == []

    def test_relationship_detection_handles_malformed_indicator(self):
        """Test that relationship detection handles malformed data gracefully"""
        detector = RelationshipDetector()

        # Missing indicator_type
        malformed = {
            "indicator_value": "test"
        }

        # Should not crash, return empty list
        relationships = detector.detect_relationships(malformed)
        assert relationships == []
