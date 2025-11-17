"""
Tests for BaseConnector abstract class

Following TDD: These tests are written FIRST before implementation
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import requests


# Will implement this after tests are written
from connectors.base import BaseConnector


class MockConnector(BaseConnector):
    """Concrete implementation of BaseConnector for testing"""

    def _get_auth_headers(self):
        return {"X-API-Key": self.api_key}

    def fetch_indicators(self, since=None):
        """Simple implementation for testing"""
        endpoint = "indicators"
        params = {}
        if since:
            params["modified_since"] = since.isoformat()
        return self._make_request(endpoint, params)


@pytest.mark.unit
class TestBaseConnectorInitialization:
    """Test connector initialization"""

    def test_initialization_with_valid_params(self):
        """Should initialize with API key and base URL"""
        connector = MockConnector(
            api_key="test-api-key-12345",
            base_url="https://api.example.com"
        )

        assert connector.api_key == "test-api-key-12345"
        assert connector.base_url == "https://api.example.com"
        assert connector.session is not None
        assert isinstance(connector.session, requests.Session)

    def test_initialization_strips_trailing_slash(self):
        """Should remove trailing slash from base_url"""
        connector = MockConnector(
            api_key="test-key",
            base_url="https://api.example.com/"
        )

        assert connector.base_url == "https://api.example.com"

    def test_auth_headers_applied_to_session(self):
        """Should apply authentication headers to session"""
        connector = MockConnector(
            api_key="secret-key",
            base_url="https://api.example.com"
        )

        assert "X-API-Key" in connector.session.headers
        assert connector.session.headers["X-API-Key"] == "secret-key"

    def test_logger_initialized(self):
        """Should initialize logger with class name"""
        connector = MockConnector("key", "https://api.example.com")

        assert connector.logger is not None
        assert connector.logger.name == "MockConnector"


@pytest.mark.unit
class TestBaseConnectorMakeRequest:
    """Test _make_request method with retry logic"""

    @patch('requests.Session.get')
    def test_make_request_success(self, mock_get):
        """Should make successful request and return JSON"""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test", "count": 5}
        mock_get.return_value = mock_response

        connector = MockConnector("key", "https://api.example.com")

        # Act
        result = connector._make_request("test/endpoint")

        # Assert
        assert result == {"data": "test", "count": 5}
        mock_get.assert_called_once()

        # Verify URL construction
        call_args = mock_get.call_args
        assert "https://api.example.com/test/endpoint" in str(call_args)

    @patch('requests.Session.get')
    def test_make_request_with_params(self, mock_get):
        """Should pass query parameters correctly"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response

        connector = MockConnector("key", "https://api.example.com")
        params = {"limit": 10, "offset": 0}

        connector._make_request("indicators", params)

        # Verify params were passed
        call_kwargs = mock_get.call_args.kwargs
        assert call_kwargs["params"] == params

    @patch('requests.Session.get')
    def test_make_request_includes_timeout(self, mock_get):
        """Should include timeout in request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response

        connector = MockConnector("key", "https://api.example.com")
        connector._make_request("test")

        call_kwargs = mock_get.call_args.kwargs
        assert "timeout" in call_kwargs
        assert call_kwargs["timeout"] == 30

    @patch('requests.Session.get')
    def test_make_request_retries_on_connection_error(self, mock_get):
        """Should retry on connection errors"""
        # Fail twice, succeed on third attempt
        mock_get.side_effect = [
            requests.exceptions.ConnectionError("Connection failed"),
            requests.exceptions.ConnectionError("Connection failed"),
            Mock(status_code=200, json=lambda: {"success": True})
        ]

        connector = MockConnector("key", "https://api.example.com")
        result = connector._make_request("test")

        assert result == {"success": True}
        assert mock_get.call_count == 3

    @patch('requests.Session.get')
    def test_make_request_retries_on_timeout(self, mock_get):
        """Should retry on timeout errors"""
        mock_get.side_effect = [
            requests.exceptions.Timeout("Request timeout"),
            Mock(status_code=200, json=lambda: {"data": "ok"})
        ]

        connector = MockConnector("key", "https://api.example.com")
        result = connector._make_request("test")

        assert result == {"data": "ok"}
        assert mock_get.call_count == 2

    @patch('requests.Session.get')
    def test_make_request_retries_on_500_error(self, mock_get):
        """Should retry on HTTP 500 errors"""
        # Create mock response with 500 status
        error_response = Mock()
        error_response.status_code = 500

        # Create HTTPError with response attached
        http_error = requests.exceptions.HTTPError("500 Server Error")
        http_error.response = error_response
        error_response.raise_for_status.side_effect = http_error

        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {"recovered": True}

        mock_get.side_effect = [error_response, success_response]

        connector = MockConnector("key", "https://api.example.com")
        result = connector._make_request("test")

        assert result == {"recovered": True}
        assert mock_get.call_count == 2

    @patch('requests.Session.get')
    def test_make_request_fails_after_max_retries(self, mock_get):
        """Should raise exception after max retries exceeded"""
        mock_get.side_effect = requests.exceptions.ConnectionError("Always fails")

        connector = MockConnector("key", "https://api.example.com")

        with pytest.raises(requests.exceptions.ConnectionError):
            connector._make_request("test")

        assert mock_get.call_count == 3  # Default max retries

    @patch('requests.Session.get')
    def test_make_request_does_not_retry_on_400_error(self, mock_get):
        """Should NOT retry on client errors (4xx)"""
        error_response = Mock()
        error_response.status_code = 400

        # Create HTTPError with response attached
        http_error = requests.exceptions.HTTPError("400 Bad Request")
        http_error.response = error_response
        error_response.raise_for_status.side_effect = http_error

        mock_get.return_value = error_response

        connector = MockConnector("key", "https://api.example.com")

        with pytest.raises(requests.exceptions.HTTPError):
            connector._make_request("test")

        # Should only try once (no retries for client errors)
        assert mock_get.call_count == 1

    @patch('requests.Session.get')
    def test_make_request_handles_leading_slash_in_endpoint(self, mock_get):
        """Should handle endpoints with leading slash"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response

        connector = MockConnector("key", "https://api.example.com")
        connector._make_request("/test/endpoint")

        # Should not double slash
        call_args = mock_get.call_args[0][0]
        assert "//" not in call_args.replace("https://", "")


@pytest.mark.unit
class TestBaseConnectorAbstractMethods:
    """Test that abstract methods must be implemented"""

    def test_cannot_instantiate_base_connector_directly(self):
        """Should not be able to instantiate abstract base class"""
        with pytest.raises(TypeError):
            BaseConnector("key", "https://api.example.com")

    def test_subclass_must_implement_get_auth_headers(self):
        """Should require _get_auth_headers implementation"""
        class IncompleteConnector(BaseConnector):
            def fetch_indicators(self, since=None):
                pass

        with pytest.raises(TypeError):
            IncompleteConnector("key", "https://api.example.com")

    def test_subclass_must_implement_fetch_indicators(self):
        """Should require fetch_indicators implementation"""
        class IncompleteConnector(BaseConnector):
            def _get_auth_headers(self):
                return {}

        with pytest.raises(TypeError):
            IncompleteConnector("key", "https://api.example.com")


@pytest.mark.unit
class TestBaseConnectorEdgeCases:
    """Test edge cases and error conditions"""

    @patch('requests.Session.get')
    def test_make_request_with_empty_response(self, mock_get):
        """Should handle empty JSON response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response

        connector = MockConnector("key", "https://api.example.com")
        result = connector._make_request("test")

        assert result == {}

    @patch('requests.Session.get')
    def test_make_request_with_malformed_json(self, mock_get):
        """Should raise exception on malformed JSON"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response

        connector = MockConnector("key", "https://api.example.com")

        with pytest.raises(ValueError):
            connector._make_request("test")
