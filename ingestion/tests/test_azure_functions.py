"""
Tests for Azure Functions (Timer and HTTP triggers)

Following TDD - Tests written FIRST
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import os
from datetime import datetime

from functions.timer_ingestion import main as timer_main
from functions.http_ingestion import main as http_main


@pytest.mark.unit
class TestTimerIngestionFunction:
    """Test timer-triggered ingestion function"""

    @patch.dict(os.environ, {'OTX_API_KEY': 'test-key', 'ABUSEIPDB_API_KEY': 'test-key'})
    @patch('functions.timer_ingestion.OTXConnector')
    @patch('functions.timer_ingestion.CosmosClient')
    def test_timer_trigger_fetches_indicators(self, mock_cosmos, mock_otx):
        """Should fetch indicators on timer trigger"""
        # Setup mocks
        mock_otx_instance = Mock()
        mock_otx_instance.fetch_indicators.return_value = [
            {
                'source': 'otx',
                'indicator_value': '1.2.3.4',
                'indicator_type': 'IPv4',
                'ingested_at': datetime.utcnow().isoformat() + 'Z'
            }
        ]
        mock_otx.return_value = mock_otx_instance

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        # Create mock timer
        mock_timer = Mock()
        mock_timer.past_due = False

        # Run function
        timer_main(mock_timer)

        # Verify connector was called
        mock_otx_instance.fetch_indicators.assert_called_once()

        # Verify data was stored
        mock_cosmos_instance.upsert_item.assert_called()

    @patch.dict(os.environ, {'OTX_API_KEY': 'test-key', 'ABUSEIPDB_API_KEY': 'test-key'})
    @patch('functions.timer_ingestion.OTXConnector')
    @patch('functions.timer_ingestion.AbuseIPDBConnector')
    @patch('functions.timer_ingestion.URLhausConnector')
    @patch('functions.timer_ingestion.CosmosClient')
    def test_fetches_from_all_sources(self, mock_cosmos, mock_urlhaus, mock_abuseipdb, mock_otx):
        """Should fetch from all configured sources"""
        # Setup mocks to return indicators
        for mock_connector_class in [mock_otx, mock_abuseipdb, mock_urlhaus]:
            mock_instance = Mock()
            mock_instance.fetch_indicators.return_value = [
                {
                    'source': 'test',
                    'indicator_value': '1.2.3.4',
                    'indicator_type': 'IPv4',
                    'ingested_at': datetime.utcnow().isoformat() + 'Z'
                }
            ]
            mock_connector_class.return_value = mock_instance

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        mock_timer = Mock()
        mock_timer.past_due = False

        # Run function
        timer_main(mock_timer)

        # Verify all connectors were used
        mock_otx.return_value.fetch_indicators.assert_called()
        mock_abuseipdb.return_value.fetch_indicators.assert_called()
        mock_urlhaus.return_value.fetch_indicators.assert_called()

    @patch('functions.timer_ingestion.OTXConnector')
    @patch('functions.timer_ingestion.CosmosClient')
    @patch('functions.timer_ingestion.logging')
    def test_handles_connector_errors_gracefully(self, mock_logging, mock_cosmos, mock_otx):
        """Should handle errors from connectors without crashing"""
        # Setup connector to raise exception
        mock_otx_instance = Mock()
        mock_otx_instance.fetch_indicators.side_effect = Exception("API error")
        mock_otx.return_value = mock_otx_instance

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        mock_timer = Mock()
        mock_timer.past_due = False

        # Should not raise exception
        timer_main(mock_timer)

        # Should log error
        mock_logging.error.assert_called()

    @patch.dict(os.environ, {'OTX_API_KEY': 'test-key'})
    @patch('functions.timer_ingestion.OTXConnector')
    @patch('functions.timer_ingestion.CosmosClient')
    @patch('functions.timer_ingestion.SchemaValidator')
    def test_validates_indicators_before_storage(self, mock_validator_class, mock_cosmos, mock_otx):
        """Should validate indicators before storing"""
        # Setup connector
        mock_otx_instance = Mock()
        mock_otx_instance.fetch_indicators.return_value = [
            {
                'source': 'otx',
                'indicator_value': '1.2.3.4',
                'indicator_type': 'IPv4',
                'ingested_at': datetime.utcnow().isoformat() + 'Z'
            }
        ]
        mock_otx.return_value = mock_otx_instance

        # Setup validator
        mock_validator = Mock()
        mock_result = Mock()
        mock_result.is_valid = True
        mock_result.validated_data = Mock()
        mock_validator.validate.return_value = mock_result
        mock_validator_class.return_value = mock_validator

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        mock_timer = Mock()
        mock_timer.past_due = False

        # Run function
        timer_main(mock_timer)

        # Verify validation was called
        mock_validator.validate.assert_called()

    @patch('functions.timer_ingestion.OTXConnector')
    @patch('functions.timer_ingestion.CosmosClient')
    def test_logs_past_due_timer(self, mock_cosmos, mock_otx):
        """Should log warning if timer is past due"""
        mock_otx_instance = Mock()
        mock_otx_instance.fetch_indicators.return_value = []
        mock_otx.return_value = mock_otx_instance

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        mock_timer = Mock()
        mock_timer.past_due = True

        with patch('functions.timer_ingestion.logging') as mock_logging:
            timer_main(mock_timer)
            mock_logging.warning.assert_called()


@pytest.mark.unit
class TestHTTPIngestionFunction:
    """Test HTTP-triggered ingestion function"""

    @patch.dict(os.environ, {'OTX_API_KEY': 'test-key'})
    @patch('functions.http_ingestion.OTXConnector')
    @patch('functions.http_ingestion.CosmosClient')
    def test_http_trigger_with_source_parameter(self, mock_cosmos, mock_otx):
        """Should fetch from specific source when provided"""
        mock_otx_instance = Mock()
        mock_otx_instance.fetch_indicators.return_value = [
            {
                'source': 'otx',
                'indicator_value': '1.2.3.4',
                'indicator_type': 'IPv4',
                'ingested_at': datetime.utcnow().isoformat() + 'Z'
            }
        ]
        mock_otx.return_value = mock_otx_instance

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        # Create HTTP request with source parameter
        mock_req = Mock()
        mock_req.params = {'source': 'otx'}
        mock_req.get_json.return_value = None

        # Run function
        response = http_main(mock_req)

        # Verify correct source was used
        mock_otx.assert_called_once()

        # Verify response
        assert response.status_code == 200

    @patch('functions.http_ingestion.CosmosClient')
    def test_http_trigger_returns_error_for_invalid_source(self, mock_cosmos):
        """Should return 400 for invalid source"""
        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        mock_req = Mock()
        mock_req.params = {'source': 'invalid_source'}
        mock_req.get_json.return_value = None

        # Run function
        response = http_main(mock_req)

        # Verify error response
        assert response.status_code == 400

    @patch.dict(os.environ, {'OTX_API_KEY': 'test-key'})
    @patch('functions.http_ingestion.OTXConnector')
    @patch('functions.http_ingestion.CosmosClient')
    def test_http_trigger_with_since_parameter(self, mock_cosmos, mock_otx):
        """Should pass 'since' parameter to connector"""
        mock_otx_instance = Mock()
        mock_otx_instance.fetch_indicators.return_value = []
        mock_otx.return_value = mock_otx_instance

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        # Create HTTP request with since parameter
        mock_req = Mock()
        mock_req.params = {
            'source': 'otx',
            'since': '2024-01-01T00:00:00Z'
        }
        mock_req.get_json.return_value = None

        # Run function
        response = http_main(mock_req)

        # Verify since was passed to connector
        mock_otx_instance.fetch_indicators.assert_called()
        call_args = mock_otx_instance.fetch_indicators.call_args
        assert call_args is not None

        assert response.status_code == 200

    @patch.dict(os.environ, {'OTX_API_KEY': 'test-key', 'ABUSEIPDB_API_KEY': 'test-key'})
    @patch('functions.http_ingestion.OTXConnector')
    @patch('functions.http_ingestion.AbuseIPDBConnector')
    @patch('functions.http_ingestion.URLhausConnector')
    @patch('functions.http_ingestion.CosmosClient')
    def test_http_trigger_without_source_uses_all(self, mock_cosmos, mock_urlhaus, mock_abuseipdb, mock_otx):
        """Should fetch from all sources when no source specified"""
        # Setup mocks
        for mock_connector_class in [mock_otx, mock_abuseipdb, mock_urlhaus]:
            mock_instance = Mock()
            mock_instance.fetch_indicators.return_value = []
            mock_connector_class.return_value = mock_instance

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        mock_req = Mock()
        mock_req.params = {}
        mock_req.get_json.return_value = None

        # Run function
        response = http_main(mock_req)

        # Verify all connectors were called
        mock_otx.return_value.fetch_indicators.assert_called()
        mock_abuseipdb.return_value.fetch_indicators.assert_called()
        mock_urlhaus.return_value.fetch_indicators.assert_called()

        assert response.status_code == 200

    @patch.dict(os.environ, {'OTX_API_KEY': 'test-key'})
    @patch('functions.http_ingestion.OTXConnector')
    @patch('functions.http_ingestion.CosmosClient')
    def test_http_trigger_returns_ingestion_stats(self, mock_cosmos, mock_otx):
        """Should return stats about ingested indicators"""
        mock_otx_instance = Mock()
        mock_otx_instance.fetch_indicators.return_value = [
            {
                'source': 'otx',
                'indicator_value': '1.2.3.4',
                'indicator_type': 'IPv4',
                'ingested_at': datetime.utcnow().isoformat() + 'Z'
            },
            {
                'source': 'otx',
                'indicator_value': '5.6.7.8',
                'indicator_type': 'IPv4',
                'ingested_at': datetime.utcnow().isoformat() + 'Z'
            }
        ]
        mock_otx.return_value = mock_otx_instance

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        mock_req = Mock()
        mock_req.params = {'source': 'otx'}
        mock_req.get_json.return_value = None

        # Run function
        response = http_main(mock_req)

        # Verify response contains stats
        assert response.status_code == 200
        response_data = json.loads(response.get_body())
        assert 'ingested_count' in response_data
        assert response_data['ingested_count'] == 2
