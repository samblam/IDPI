"""
Tests for URLhausConnector

Following TDD
"""
import pytest
from unittest.mock import Mock, patch
import json
import os

from connectors.urlhaus_connector import URLhausConnector


def load_fixture(filename):
    """Load test fixture"""
    fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', filename)
    with open(fixture_path, 'r') as f:
        return json.load(f)


@pytest.mark.unit
class TestURLhausConnector:
    """Test URLhaus connector"""

    def test_initialization(self):
        """Should initialize without API key"""
        connector = URLhausConnector()
        assert connector.base_url == "https://urlhaus-api.abuse.ch/v1"

    def test_no_auth_headers(self):
        """Should not require authentication"""
        connector = URLhausConnector()
        # Should have empty auth headers
        assert connector._get_auth_headers() == {}

    @patch('requests.Session.get')
    def test_fetch_indicators(self, mock_get):
        """Should fetch and parse URLs"""
        response = load_fixture('urlhaus_response.json')
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = response
        mock_get.return_value = mock_response

        connector = URLhausConnector()
        indicators = connector.fetch_indicators()

        assert len(indicators) == 2
        assert all(ind['source'] == 'urlhaus' for ind in indicators)
        assert all(ind['indicator_type'] == 'URL' for ind in indicators)

    @patch('requests.Session.get')
    def test_includes_tags(self, mock_get):
        """Should include tags from URLhaus"""
        response = load_fixture('urlhaus_response.json')
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = response
        mock_get.return_value = mock_response

        connector = URLhausConnector()
        indicators = connector.fetch_indicators()

        first = indicators[0]
        assert 'tags' in first
        assert 'malware' in first['tags']
