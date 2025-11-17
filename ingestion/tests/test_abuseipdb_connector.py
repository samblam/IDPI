"""
Tests for AbuseIPDBConnector

Following TDD
"""
import pytest
from unittest.mock import Mock, patch
import json
import os

from connectors.abuseipdb_connector import AbuseIPDBConnector


def load_fixture(filename):
    """Load test fixture"""
    fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', filename)
    with open(fixture_path, 'r') as f:
        return json.load(f)


@pytest.mark.unit
class TestAbuseIPDBConnector:
    """Test AbuseIPDB connector"""

    def test_initialization(self):
        """Should initialize with API key"""
        connector = AbuseIPDBConnector(api_key="test-key")
        assert connector.api_key == "test-key"
        assert connector.base_url == "https://api.abuseipdb.com/api/v2"

    def test_auth_headers_uses_key_header(self):
        """Should use Key header"""
        connector = AbuseIPDBConnector(api_key="secret")
        assert connector.session.headers["Key"] == "secret"

    @patch('requests.Session.get')
    def test_fetch_indicators(self, mock_get):
        """Should fetch and parse blacklist"""
        response = load_fixture('abuseipdb_response.json')
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = response
        mock_get.return_value = mock_response

        connector = AbuseIPDBConnector("test-key")
        indicators = connector.fetch_indicators()

        assert len(indicators) == 2
        assert all(ind['source'] == 'abuseipdb' for ind in indicators)
        assert indicators[0]['indicator_value'] == '1.2.3.4'
        assert indicators[0]['confidence'] == 100

    @patch('requests.Session.get')
    def test_includes_metadata(self, mock_get):
        """Should include AbuseIPDB metadata"""
        response = load_fixture('abuseipdb_response.json')
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = response
        mock_get.return_value = mock_response

        connector = AbuseIPDBConnector("test-key")
        indicators = connector.fetch_indicators()

        first = indicators[0]
        assert 'total_reports' in first['raw_metadata']
        assert first['raw_metadata']['total_reports'] == 25
