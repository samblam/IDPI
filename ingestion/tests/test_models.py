"""
Tests for Pydantic data models

Following TDD: Write tests FIRST
"""
import pytest
from datetime import datetime
from pydantic import ValidationError

# Will implement after tests
from models.raw_indicator import RawIndicator
from models.schemas import OTXIndicatorSchema, OTXPulseSchema, AbuseIPDBDataSchema


@pytest.mark.unit
class TestRawIndicator:
    """Test RawIndicator model"""

    def test_valid_raw_indicator(self):
        """Should create valid indicator with all fields"""
        data = {
            "source": "otx",
            "indicator_value": "1.2.3.4",
            "indicator_type": "IPv4",
            "confidence": 75,
            "tags": ["malware", "botnet"],
            "ingested_at": "2024-01-01T12:00:00Z",
            "raw_metadata": {"pulse_id": "123", "description": "Test"}
        }

        indicator = RawIndicator(**data)

        assert indicator.source == "otx"
        assert indicator.indicator_value == "1.2.3.4"
        assert indicator.indicator_type == "IPv4"
        assert indicator.confidence == 75
        assert len(indicator.tags) == 2
        assert indicator.raw_metadata["pulse_id"] == "123"

    def test_minimal_raw_indicator(self):
        """Should create indicator with only required fields"""
        data = {
            "source": "otx",
            "indicator_value": "example.com",
            "indicator_type": "domain",
            "ingested_at": "2024-01-01T12:00:00Z"
        }

        indicator = RawIndicator(**data)

        assert indicator.source == "otx"
        assert indicator.indicator_value == "example.com"
        # Optional fields should have defaults
        assert indicator.confidence is None or indicator.confidence >= 0
        assert indicator.tags == []
        assert indicator.raw_metadata == {}

    def test_missing_required_fields_raises_error(self):
        """Should raise ValidationError when required fields missing"""
        data = {
            "source": "otx",
            # Missing indicator_value
            "indicator_type": "IPv4"
        }

        with pytest.raises(ValidationError) as exc_info:
            RawIndicator(**data)

        assert "indicator_value" in str(exc_info.value)

    def test_invalid_indicator_type_raises_error(self):
        """Should validate indicator_type enum"""
        data = {
            "source": "otx",
            "indicator_value": "test",
            "indicator_type": "INVALID_TYPE",  # Not in enum
            "ingested_at": "2024-01-01T12:00:00Z"
        }

        with pytest.raises(ValidationError) as exc_info:
            RawIndicator(**data)

        assert "indicator_type" in str(exc_info.value)

    def test_confidence_range_validation(self):
        """Should validate confidence is between 0-100"""
        # Test below range
        with pytest.raises(ValidationError):
            RawIndicator(
                source="otx",
                indicator_value="test",
                indicator_type="IPv4",
                confidence=-1,
                ingested_at="2024-01-01T12:00:00Z"
            )

        # Test above range
        with pytest.raises(ValidationError):
            RawIndicator(
                source="otx",
                indicator_value="test",
                indicator_type="IPv4",
                confidence=101,
                ingested_at="2024-01-01T12:00:00Z"
            )

        # Test valid values
        indicator = RawIndicator(
            source="otx",
            indicator_value="test",
            indicator_type="IPv4",
            confidence=50,
            ingested_at="2024-01-01T12:00:00Z"
        )
        assert indicator.confidence == 50

    def test_dict_export(self):
        """Should export to dictionary correctly"""
        data = {
            "source": "otx",
            "indicator_value": "1.2.3.4",
            "indicator_type": "IPv4",
            "confidence": 85,
            "tags": ["test"],
            "ingested_at": "2024-01-01T12:00:00Z",
            "raw_metadata": {"key": "value"}
        }

        indicator = RawIndicator(**data)
        exported = indicator.model_dump()

        assert exported["source"] == "otx"
        assert exported["indicator_value"] == "1.2.3.4"
        assert exported["confidence"] == 85


@pytest.mark.unit
class TestOTXIndicatorSchema:
    """Test OTX indicator validation schema"""

    def test_valid_otx_indicator(self):
        """Should validate OTX indicator structure"""
        data = {
            "indicator": "1.2.3.4",
            "type": "IPv4",
            "description": "Malicious IP"
        }

        schema = OTXIndicatorSchema(**data)

        assert schema.indicator == "1.2.3.4"
        assert schema.type == "IPv4"
        assert schema.description == "Malicious IP"

    def test_otx_indicator_valid_types(self):
        """Should accept all valid OTX indicator types"""
        valid_types = [
            "IPv4", "IPv6", "domain", "hostname", "URL",
            "FileHash-MD5", "FileHash-SHA256"
        ]

        for indicator_type in valid_types:
            data = {
                "indicator": "test_value",
                "type": indicator_type
            }
            schema = OTXIndicatorSchema(**data)
            assert schema.type == indicator_type

    def test_otx_indicator_invalid_type_raises_error(self):
        """Should reject invalid indicator types"""
        data = {
            "indicator": "test",
            "type": "INVALID_TYPE"
        }

        with pytest.raises(ValidationError) as exc_info:
            OTXIndicatorSchema(**data)

        assert "type" in str(exc_info.value)

    def test_otx_indicator_empty_description_allowed(self):
        """Should allow empty description (optional)"""
        data = {
            "indicator": "test",
            "type": "IPv4"
        }

        schema = OTXIndicatorSchema(**data)
        assert schema.description == "" or schema.description is None


@pytest.mark.unit
class TestOTXPulseSchema:
    """Test OTX pulse validation schema"""

    def test_valid_otx_pulse(self):
        """Should validate OTX pulse structure"""
        data = {
            "id": "pulse123",
            "name": "Test Pulse",
            "TLP": "white",
            "tags": ["malware", "apt"],
            "indicators": [
                {"indicator": "1.2.3.4", "type": "IPv4"}
            ],
            "description": "Test pulse description"
        }

        pulse = OTXPulseSchema(**data)

        assert pulse.id == "pulse123"
        assert pulse.name == "Test Pulse"
        assert pulse.TLP == "white"
        assert len(pulse.tags) == 2
        assert len(pulse.indicators) == 1

    def test_otx_pulse_minimal_required_fields(self):
        """Should create pulse with minimal required fields"""
        data = {
            "id": "pulse123",
            "name": "Test Pulse",
            "indicators": []
        }

        pulse = OTXPulseSchema(**data)

        assert pulse.id == "pulse123"
        assert pulse.name == "Test Pulse"
        assert pulse.TLP == "unknown"  # Default value
        assert pulse.tags == []
        assert pulse.indicators == []

    def test_otx_pulse_allows_extra_fields(self):
        """Should allow extra fields (API may add new fields)"""
        data = {
            "id": "pulse123",
            "name": "Test Pulse",
            "indicators": [],
            "extra_field": "this should be allowed",
            "another_field": 123
        }

        # Should not raise error
        pulse = OTXPulseSchema(**data)
        assert pulse.id == "pulse123"


@pytest.mark.unit
class TestAbuseIPDBDataSchema:
    """Test AbuseIPDB data validation schema"""

    def test_valid_abuseipdb_data(self):
        """Should validate AbuseIPDB data structure"""
        data = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 95,
            "totalReports": 10,
            "lastReportedAt": "2024-01-01T12:00:00+00:00"
        }

        schema = AbuseIPDBDataSchema(**data)

        assert schema.ipAddress == "1.2.3.4"
        assert schema.abuseConfidenceScore == 95
        assert schema.totalReports == 10

    def test_abuseipdb_confidence_score_range(self):
        """Should validate abuseConfidenceScore is 0-100"""
        # Valid
        data = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 50,
            "totalReports": 5
        }
        schema = AbuseIPDBDataSchema(**data)
        assert schema.abuseConfidenceScore == 50

        # Invalid - below range
        with pytest.raises(ValidationError):
            AbuseIPDBDataSchema(
                ipAddress="1.2.3.4",
                abuseConfidenceScore=-1,
                totalReports=5
            )

        # Invalid - above range
        with pytest.raises(ValidationError):
            AbuseIPDBDataSchema(
                ipAddress="1.2.3.4",
                abuseConfidenceScore=101,
                totalReports=5
            )

    def test_abuseipdb_total_reports_non_negative(self):
        """Should validate totalReports is non-negative"""
        with pytest.raises(ValidationError):
            AbuseIPDBDataSchema(
                ipAddress="1.2.3.4",
                abuseConfidenceScore=50,
                totalReports=-1
            )


@pytest.mark.unit
class TestModelSerialization:
    """Test model serialization/deserialization"""

    def test_raw_indicator_json_serialization(self):
        """Should serialize to JSON correctly"""
        data = {
            "source": "otx",
            "indicator_value": "1.2.3.4",
            "indicator_type": "IPv4",
            "confidence": 85,
            "tags": ["test"],
            "ingested_at": "2024-01-01T12:00:00Z",
            "raw_metadata": {"key": "value"}
        }

        indicator = RawIndicator(**data)
        json_str = indicator.model_dump_json()

        assert "1.2.3.4" in json_str
        assert "otx" in json_str
        assert "85" in json_str

    def test_raw_indicator_from_json(self):
        """Should deserialize from JSON correctly"""
        json_str = '{"source": "otx", "indicator_value": "test.com", "indicator_type": "domain", "ingested_at": "2024-01-01T12:00:00Z"}'

        indicator = RawIndicator.model_validate_json(json_str)

        assert indicator.source == "otx"
        assert indicator.indicator_value == "test.com"
        assert indicator.indicator_type == "domain"
