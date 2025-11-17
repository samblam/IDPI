"""
Tests for OTXConnector

Following TDD: Write tests FIRST
"""
import pytest
from unittest.mock import Mock, patch
from datetime import datetime
import json
import os

from connectors.otx_connector import OTXConnector


def load_fixture(filename):
    """Load test fixture from file"""
    fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', filename)
    with open(fixture_path, 'r') as f:
        return json.load(f)


@pytest.mark.unit
class TestOTXConnectorInitialization:
    """Test OTX connector initialization"""

    def test_initialization_with_api_key(self):
        """Should initialize with API key"""
        connector = OTXConnector(api_key="test-otx-key")

        assert connector.api_key == "test-otx-key"
        assert connector.base_url == "https://otx.alienvault.com/api/v1"
        assert connector.session is not None

    def test_auth_headers_uses_x_otx_api_key(self):
        """Should use X-OTX-API-Key header"""
        connector = OTXConnector(api_key="secret-key")

        assert "X-OTX-API-Key" in connector.session.headers
        assert connector.session.headers["X-OTX-API-Key"] == "secret-key"


@pytest.mark.unit
class TestOTXConnectorFetchIndicators:
    """Test fetching indicators from OTX"""

    @patch('requests.Session.get')
    def test_fetch_indicators_without_since_param(self, mock_get):
        """Should fetch indicators without time filter"""
        # Arrange
        otx_response = load_fixture('otx_response.json')
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = otx_response
        mock_get.return_value = mock_response

        connector = OTXConnector("test-key")

        # Act
        indicators = connector.fetch_indicators()

        # Assert
        assert len(indicators) == 3  # 2 + 1 + 0 from two pulses
        assert all(ind['source'] == 'otx' for ind in indicators)

        # Verify endpoint called
        call_args = mock_get.call_args
        assert 'pulses/subscribed' in str(call_args)

    @patch('requests.Session.get')
    def test_fetch_indicators_with_since_param(self, mock_get):
        """Should pass modified_since parameter"""
        otx_response = load_fixture('otx_response.json')
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = otx_response
        mock_get.return_value = mock_response

        connector = OTXConnector("test-key")
        since = datetime(2024, 1, 1, 12, 0, 0)

        connector.fetch_indicators(since=since)

        # Verify params passed
        call_kwargs = mock_get.call_args.kwargs
        assert 'params' in call_kwargs
        assert 'modified_since' in call_kwargs['params']
        assert call_kwargs['params']['modified_since'] == "2024-01-01T12:00:00"

    @patch('requests.Session.get')
    def test_fetch_indicators_returns_normalized_format(self, mock_get):
        """Should return indicators in normalized format"""
        otx_response = load_fixture('otx_response.json')
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = otx_response
        mock_get.return_value = mock_response

        connector = OTXConnector("test-key")
        indicators = connector.fetch_indicators()

        # Check first indicator
        first = indicators[0]
        assert first['source'] == 'otx'
        assert first['indicator_value'] == '1.2.3.4'
        assert first['indicator_type'] == 'IPv4'
        assert 'ingested_at' in first
        assert 'raw_metadata' in first
        assert first['raw_metadata']['pulse_id'] == 'pulse123'
        assert first['raw_metadata']['pulse_name'] == 'Malicious Campaign'

    @patch('requests.Session.get')
    def test_fetch_indicators_includes_pulse_metadata(self, mock_get):
        """Should include pulse metadata in raw_metadata"""
        otx_response = load_fixture('otx_response.json')
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = otx_response
        mock_get.return_value = mock_response

        connector = OTXConnector("test-key")
        indicators = connector.fetch_indicators()

        first = indicators[0]
        metadata = first['raw_metadata']

        assert 'pulse_id' in metadata
        assert 'pulse_name' in metadata
        assert 'tlp' in metadata
        assert 'tags' in metadata
        assert metadata['tlp'] == 'white'
        assert 'malware' in metadata['tags']

    @patch('requests.Session.get')
    def test_fetch_indicators_handles_empty_results(self, mock_get):
        """Should handle empty results gracefully"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"count": 0, "results": []}
        mock_get.return_value = mock_response

        connector = OTXConnector("test-key")
        indicators = connector.fetch_indicators()

        assert indicators == []

    @patch('requests.Session.get')
    def test_fetch_indicators_handles_pulse_without_indicators(self, mock_get):
        """Should skip pulses with no indicators"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "count": 1,
            "results": [
                {
                    "id": "empty_pulse",
                    "name": "Empty",
                    "indicators": []
                }
            ]
        }
        mock_get.return_value = mock_response

        connector = OTXConnector("test-key")
        indicators = connector.fetch_indicators()

        assert indicators == []

    @patch('requests.Session.get')
    def test_fetch_indicators_sets_ingested_at_timestamp(self, mock_get):
        """Should set ingested_at timestamp"""
        otx_response = load_fixture('otx_response.json')
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = otx_response
        mock_get.return_value = mock_response

        connector = OTXConnector("test-key")

        before = datetime.utcnow()
        indicators = connector.fetch_indicators()
        after = datetime.utcnow()

        # Verify timestamp is recent
        for indicator in indicators:
            ingested = datetime.fromisoformat(indicator['ingested_at'].replace('Z', '+00:00'))
            assert before <= ingested.replace(tzinfo=None) <= after


@pytest.mark.unit
class TestOTXConnectorErrorHandling:
    """Test error handling"""

    @patch('requests.Session.get')
    def test_fetch_indicators_raises_on_invalid_api_key(self, mock_get):
        """Should raise exception on 401/403"""
        mock_response = Mock()
        mock_response.status_code = 403
        http_error = Exception("403 Forbidden")
        http_error.response = mock_response
        mock_response.raise_for_status.side_effect = http_error
        mock_get.return_value = mock_response

        connector = OTXConnector("invalid-key")

        with pytest.raises(Exception):
            connector.fetch_indicators()

    @patch('requests.Session.get')
    def test_fetch_indicators_handles_malformed_response(self, mock_get):
        """Should handle malformed JSON response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"unexpected": "format"}  # Missing 'results'
        mock_get.return_value = mock_response

        connector = OTXConnector("test-key")

        # Should either return empty list or raise clear error
        result = connector.fetch_indicators()
        assert isinstance(result, list)
