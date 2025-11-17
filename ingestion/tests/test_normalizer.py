"""
Tests for Indicator Normalizer

Following TDD - Tests written FIRST
"""
import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from normalization.normalizer import IndicatorNormalizer


@pytest.mark.unit
class TestIndicatorTypeDetection:
    """Test indicator type detection from values"""

    def test_detect_ipv4_address(self):
        """Should detect IPv4 addresses"""
        normalizer = IndicatorNormalizer()

        assert normalizer.detect_type("192.168.1.1") == "IPv4"
        assert normalizer.detect_type("8.8.8.8") == "IPv4"
        assert normalizer.detect_type("10.0.0.1") == "IPv4"

    def test_detect_ipv6_address(self):
        """Should detect IPv6 addresses"""
        normalizer = IndicatorNormalizer()

        assert normalizer.detect_type("2001:0db8:85a3::8a2e:0370:7334") == "IPv6"
        assert normalizer.detect_type("::1") == "IPv6"
        assert normalizer.detect_type("fe80::1") == "IPv6"

    def test_detect_domain(self):
        """Should detect domain names"""
        normalizer = IndicatorNormalizer()

        assert normalizer.detect_type("example.com") == "domain"
        assert normalizer.detect_type("malicious-site.org") == "domain"
        assert normalizer.detect_type("sub.domain.co.uk") == "domain"

    def test_detect_url(self):
        """Should detect URLs"""
        normalizer = IndicatorNormalizer()

        assert normalizer.detect_type("http://malicious.com/path") == "URL"
        assert normalizer.detect_type("https://evil.org/malware.exe") == "URL"

    def test_detect_md5_hash(self):
        """Should detect MD5 hashes"""
        normalizer = IndicatorNormalizer()

        assert normalizer.detect_type("5d41402abc4b2a76b9719d911017c592") == "MD5"

    def test_detect_sha256_hash(self):
        """Should detect SHA256 hashes"""
        normalizer = IndicatorNormalizer()

        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert normalizer.detect_type(sha256) == "SHA256"

    def test_unknown_type_returns_unknown(self):
        """Should return Unknown for unrecognized types"""
        normalizer = IndicatorNormalizer()

        assert normalizer.detect_type("not-a-valid-indicator") == "Unknown"
        assert normalizer.detect_type("") == "Unknown"


@pytest.mark.unit
class TestOTXNormalization:
    """Test OTX indicator normalization"""

    @pytest.fixture
    def raw_otx_indicator(self):
        """Sample raw OTX indicator"""
        return {
            "source": "otx",
            "indicator_value": "192.168.1.1",
            "indicator_type": "IPv4",
            "ingested_at": "2024-01-01T12:00:00Z",
            "raw_metadata": {
                "pulse_id": "abc123",
                "pulse_name": "Malicious Campaign",
                "tlp": "amber",
                "tags": ["malware", "botnet"],
                "description": "C2 server"
            }
        }

    def test_normalize_otx_indicator(self, raw_otx_indicator):
        """Should normalize OTX indicator to common schema"""
        normalizer = IndicatorNormalizer()

        normalized = normalizer.normalize(raw_otx_indicator)

        assert normalized["indicator_value"] == "192.168.1.1"
        assert normalized["indicator_type"] == "IPv4"
        assert "sources" in normalized
        assert len(normalized["sources"]) == 1
        assert normalized["sources"][0]["name"] == "otx"

    def test_otx_tlp_to_confidence_mapping(self, raw_otx_indicator):
        """Should map TLP levels to confidence scores"""
        normalizer = IndicatorNormalizer()

        # Test different TLP levels
        test_cases = [
            ("red", 90),
            ("amber", 70),
            ("green", 50),
            ("white", 30),
            ("unknown", 40)
        ]

        for tlp, expected_score in test_cases:
            raw_otx_indicator["raw_metadata"]["tlp"] = tlp
            normalized = normalizer.normalize(raw_otx_indicator)
            assert normalized["confidence_score"] == expected_score

    def test_otx_preserves_metadata(self, raw_otx_indicator):
        """Should preserve important metadata in sources"""
        normalizer = IndicatorNormalizer()

        normalized = normalizer.normalize(raw_otx_indicator)
        source = normalized["sources"][0]

        assert source["pulse_id"] == "abc123"
        assert source["pulse_name"] == "Malicious Campaign"
        assert "malware" in source["tags"]
        assert source["description"] == "C2 server"

    def test_otx_sets_first_and_last_seen(self, raw_otx_indicator):
        """Should set first_seen and last_seen timestamps"""
        normalizer = IndicatorNormalizer()

        normalized = normalizer.normalize(raw_otx_indicator)

        assert normalized["first_seen"] == "2024-01-01T12:00:00Z"
        assert normalized["last_seen"] == "2024-01-01T12:00:00Z"


@pytest.mark.unit
class TestAbuseIPDBNormalization:
    """Test AbuseIPDB indicator normalization"""

    @pytest.fixture
    def raw_abuseipdb_indicator(self):
        """Sample raw AbuseIPDB indicator"""
        return {
            "source": "abuseipdb",
            "indicator_value": "1.2.3.4",
            "indicator_type": "IPv4",
            "confidence": 95,
            "ingested_at": "2024-01-01T12:00:00Z",
            "raw_metadata": {
                "abuse_confidence_score": 95,
                "total_reports": 150,
                "last_reported_at": "2024-01-01T11:00:00Z"
            }
        }

    def test_normalize_abuseipdb_indicator(self, raw_abuseipdb_indicator):
        """Should normalize AbuseIPDB indicator"""
        normalizer = IndicatorNormalizer()

        normalized = normalizer.normalize(raw_abuseipdb_indicator)

        assert normalized["indicator_value"] == "1.2.3.4"
        assert normalized["indicator_type"] == "IPv4"
        assert normalized["sources"][0]["name"] == "abuseipdb"

    def test_abuseipdb_confidence_mapping(self, raw_abuseipdb_indicator):
        """Should use abuse confidence score directly"""
        normalizer = IndicatorNormalizer()

        normalized = normalizer.normalize(raw_abuseipdb_indicator)

        # AbuseIPDB score should be used directly (0-100)
        assert normalized["confidence_score"] == 95

    def test_abuseipdb_preserves_report_count(self, raw_abuseipdb_indicator):
        """Should preserve total report count"""
        normalizer = IndicatorNormalizer()

        normalized = normalizer.normalize(raw_abuseipdb_indicator)
        source = normalized["sources"][0]

        assert source["total_reports"] == 150
        assert source["abuse_confidence_score"] == 95


@pytest.mark.unit
class TestURLhausNormalization:
    """Test URLhaus indicator normalization"""

    @pytest.fixture
    def raw_urlhaus_indicator(self):
        """Sample raw URLhaus indicator"""
        return {
            "source": "urlhaus",
            "indicator_value": "http://evil.com/malware.exe",
            "indicator_type": "URL",
            "ingested_at": "2024-01-01T12:00:00Z",
            "raw_metadata": {
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["exe", "malware"]
            }
        }

    def test_normalize_urlhaus_indicator(self, raw_urlhaus_indicator):
        """Should normalize URLhaus indicator"""
        normalizer = IndicatorNormalizer()

        normalized = normalizer.normalize(raw_urlhaus_indicator)

        assert normalized["indicator_value"] == "http://evil.com/malware.exe"
        assert normalized["indicator_type"] == "URL"
        assert normalized["sources"][0]["name"] == "urlhaus"

    def test_urlhaus_confidence_based_on_status(self, raw_urlhaus_indicator):
        """Should map URL status to confidence score"""
        normalizer = IndicatorNormalizer()

        # Online threats = higher confidence
        normalized = normalizer.normalize(raw_urlhaus_indicator)
        assert normalized["confidence_score"] == 80

        # Offline threats = lower confidence
        raw_urlhaus_indicator["raw_metadata"]["url_status"] = "offline"
        normalized = normalizer.normalize(raw_urlhaus_indicator)
        assert normalized["confidence_score"] == 50

    def test_urlhaus_preserves_threat_type(self, raw_urlhaus_indicator):
        """Should preserve threat type in metadata"""
        normalizer = IndicatorNormalizer()

        normalized = normalizer.normalize(raw_urlhaus_indicator)
        source = normalized["sources"][0]

        assert source["threat"] == "malware_download"
        assert "exe" in source["tags"]


@pytest.mark.unit
class TestNormalizerEdgeCases:
    """Test normalizer edge cases"""

    def test_unknown_source_raises_error(self):
        """Should raise error for unknown source"""
        normalizer = IndicatorNormalizer()

        raw_indicator = {
            "source": "unknown_source",
            "indicator_value": "1.2.3.4"
        }

        with pytest.raises(ValueError, match="Unknown source"):
            normalizer.normalize(raw_indicator)

    def test_missing_required_fields_raises_error(self):
        """Should raise error when required fields missing"""
        normalizer = IndicatorNormalizer()

        raw_indicator = {
            "source": "otx"
            # Missing indicator_value
        }

        with pytest.raises(KeyError):
            normalizer.normalize(raw_indicator)

    def test_generates_deterministic_id(self):
        """Should generate deterministic ID from source and value"""
        normalizer = IndicatorNormalizer()

        raw_indicator = {
            "source": "otx",
            "indicator_value": "192.168.1.1",
            "indicator_type": "IPv4",
            "ingested_at": "2024-01-01T12:00:00Z",
            "raw_metadata": {"tlp": "green"}
        }

        normalized1 = normalizer.normalize(raw_indicator)
        normalized2 = normalizer.normalize(raw_indicator)

        assert normalized1["id"] == normalized2["id"]
        assert normalized1["id"] == "norm_otx_192.168.1.1"

    def test_normalized_at_timestamp_set(self):
        """Should set normalized_at timestamp"""
        normalizer = IndicatorNormalizer()

        raw_indicator = {
            "source": "otx",
            "indicator_value": "192.168.1.1",
            "indicator_type": "IPv4",
            "ingested_at": "2024-01-01T12:00:00Z",
            "raw_metadata": {"tlp": "green"}
        }

        normalized = normalizer.normalize(raw_indicator)

        assert "normalized_at" in normalized
        # Should be recent timestamp
        normalized_time = datetime.fromisoformat(normalized["normalized_at"].replace("Z", "+00:00"))
        assert (datetime.utcnow().replace(tzinfo=normalized_time.tzinfo) - normalized_time).total_seconds() < 2
