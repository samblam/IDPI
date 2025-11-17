"""
Tests for Schema Validator

Following TDD - Tests written FIRST
"""
import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from utils.schema_validator import SchemaValidator, ValidationResult
from models.raw_indicator import RawIndicator
from models.schemas import OTXPulseResponse, AbuseIPDBResponse


@pytest.mark.unit
class TestSchemaValidator:
    """Test schema validator utility"""

    def test_initialization(self):
        """Should initialize validator"""
        validator = SchemaValidator()
        assert validator is not None

    def test_validate_valid_data(self):
        """Should validate correct data successfully"""
        validator = SchemaValidator()

        valid_data = {
            'source': 'otx',
            'indicator_value': '1.2.3.4',
            'indicator_type': 'IPv4',
            'ingested_at': datetime.utcnow().isoformat() + 'Z'
        }

        result = validator.validate(valid_data, RawIndicator)

        assert result.is_valid is True
        assert result.errors == []
        assert result.validated_data is not None

    def test_validate_invalid_data(self):
        """Should return validation errors for invalid data"""
        validator = SchemaValidator()

        invalid_data = {
            'source': 'otx',
            'indicator_value': '',  # Empty string should fail
            'indicator_type': 'INVALID_TYPE',
            'ingested_at': 'not-a-date'
        }

        result = validator.validate(invalid_data, RawIndicator)

        assert result.is_valid is False
        assert len(result.errors) > 0
        assert result.validated_data is None

    def test_validate_missing_required_field(self):
        """Should fail when required field missing"""
        validator = SchemaValidator()

        incomplete_data = {
            'source': 'otx',
            'indicator_value': '1.2.3.4'
            # Missing indicator_type (required)
        }

        result = validator.validate(incomplete_data, RawIndicator)

        assert result.is_valid is False
        assert any('indicator_type' in str(err) for err in result.errors)

    def test_validate_batch_all_valid(self):
        """Should validate batch of items successfully"""
        validator = SchemaValidator()

        batch = [
            {
                'source': 'otx',
                'indicator_value': '1.2.3.4',
                'indicator_type': 'IPv4',
                'ingested_at': datetime.utcnow().isoformat() + 'Z'
            },
            {
                'source': 'otx',
                'indicator_value': 'evil.com',
                'indicator_type': 'domain',
                'ingested_at': datetime.utcnow().isoformat() + 'Z'
            }
        ]

        results = validator.validate_batch(batch, RawIndicator)

        assert len(results) == 2
        assert all(r.is_valid for r in results)

    def test_validate_batch_mixed_valid_invalid(self):
        """Should handle batch with some invalid items"""
        validator = SchemaValidator()

        batch = [
            {
                'source': 'otx',
                'indicator_value': '1.2.3.4',
                'indicator_type': 'IPv4',
                'ingested_at': datetime.utcnow().isoformat() + 'Z'
            },
            {
                'source': 'otx',
                'indicator_value': '',  # Invalid
                'indicator_type': 'IPv4',
                'ingested_at': datetime.utcnow().isoformat() + 'Z'
            }
        ]

        results = validator.validate_batch(batch, RawIndicator)

        assert len(results) == 2
        assert results[0].is_valid is True
        assert results[1].is_valid is False

    def test_validation_result_summary(self):
        """Should provide summary of validation results"""
        validator = SchemaValidator()

        batch = [
            {'source': 'otx', 'indicator_value': '1.2.3.4', 'indicator_type': 'IPv4', 'ingested_at': datetime.utcnow().isoformat() + 'Z'},
            {'source': 'otx', 'indicator_value': '', 'indicator_type': 'IPv4', 'ingested_at': datetime.utcnow().isoformat() + 'Z'},
            {'source': 'otx', 'indicator_value': 'evil.com', 'indicator_type': 'domain', 'ingested_at': datetime.utcnow().isoformat() + 'Z'}
        ]

        results = validator.validate_batch(batch, RawIndicator)
        summary = validator.get_batch_summary(results)

        assert summary['total'] == 3
        assert summary['valid'] == 2
        assert summary['invalid'] == 1
        assert summary['success_rate'] == pytest.approx(66.67, rel=0.1)

    def test_strict_mode_raises_on_invalid(self):
        """Should raise exception in strict mode"""
        validator = SchemaValidator(strict=True)

        invalid_data = {
            'source': 'otx',
            'indicator_value': '',
            'indicator_type': 'IPv4',
            'ingested_at': datetime.utcnow().isoformat() + 'Z'
        }

        with pytest.raises(ValueError):
            validator.validate(invalid_data, RawIndicator)

    def test_logs_validation_failures(self):
        """Should log validation failures"""
        validator = SchemaValidator()

        invalid_data = {
            'source': 'otx',
            'indicator_value': '',
            'indicator_type': 'INVALID',
            'ingested_at': 'bad-date'
        }

        with patch.object(validator.logger, 'warning') as mock_log:
            result = validator.validate(invalid_data, RawIndicator)

            assert result.is_valid is False
            mock_log.assert_called()

    def test_validate_otx_response_schema(self):
        """Should validate OTX API response format"""
        validator = SchemaValidator()

        otx_response = {
            'results': [
                {
                    'id': '123',
                    'name': 'Test Pulse',
                    'indicators': [
                        {'indicator': '1.2.3.4', 'type': 'IPv4'}
                    ]
                }
            ]
        }

        result = validator.validate(otx_response, OTXPulseResponse)
        assert result.is_valid is True

    def test_validate_abuseipdb_response_schema(self):
        """Should validate AbuseIPDB API response format"""
        validator = SchemaValidator()

        abuseipdb_response = {
            'data': [
                {
                    'ipAddress': '1.2.3.4',
                    'abuseConfidenceScore': 100,
                    'totalReports': 25
                }
            ]
        }

        result = validator.validate(abuseipdb_response, AbuseIPDBResponse)
        assert result.is_valid is True

    def test_extract_valid_items_from_batch(self):
        """Should extract only valid items from batch"""
        validator = SchemaValidator()

        batch = [
            {'source': 'otx', 'indicator_value': '1.2.3.4', 'indicator_type': 'IPv4', 'ingested_at': datetime.utcnow().isoformat() + 'Z'},
            {'source': 'otx', 'indicator_value': '', 'indicator_type': 'IPv4', 'ingested_at': datetime.utcnow().isoformat() + 'Z'},
            {'source': 'otx', 'indicator_value': 'evil.com', 'indicator_type': 'domain', 'ingested_at': datetime.utcnow().isoformat() + 'Z'}
        ]

        results = validator.validate_batch(batch, RawIndicator)
        valid_items = validator.get_valid_items(results)

        assert len(valid_items) == 2
        assert all(item.indicator_value != '' for item in valid_items)

    def test_handles_pydantic_validation_error(self):
        """Should handle Pydantic ValidationError gracefully"""
        validator = SchemaValidator()

        # Data with wrong type for confidence
        bad_data = {
            'source': 'otx',
            'indicator_value': '1.2.3.4',
            'indicator_type': 'IPv4',
            'confidence': 'not-a-number',  # Should be int
            'ingested_at': datetime.utcnow().isoformat() + 'Z'
        }

        result = validator.validate(bad_data, RawIndicator)

        assert result.is_valid is False
        assert len(result.errors) > 0
