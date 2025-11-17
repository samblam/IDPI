"""
Base connector for threat intelligence sources

This abstract base class provides common functionality for all connectors:
- HTTP session management with authentication
- Automatic retry logic for transient failures
- Structured logging
- Timeout handling
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from datetime import datetime
import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception
)
import logging


def _should_retry_exception(exception):
    """
    Determine if exception should trigger a retry

    Retry on:
    - ConnectionError
    - Timeout
    - HTTPError with 5xx status (server errors)

    Do NOT retry on:
    - HTTPError with 4xx status (client errors)
    """
    if isinstance(exception, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
        return True

    if isinstance(exception, requests.exceptions.HTTPError):
        # Only retry if it's a server error (5xx)
        if exception.response is not None and exception.response.status_code >= 500:
            return True
        return False

    return False


class BaseConnector(ABC):
    """
    Abstract base class for threat intelligence connectors

    Subclasses must implement:
    - _get_auth_headers(): Return authentication headers
    - fetch_indicators(): Fetch and parse indicators from the source
    """

    # Class-level configuration
    DEFAULT_TIMEOUT = 30  # seconds
    MAX_RETRIES = 3
    RETRY_MULTIPLIER = 1
    RETRY_MIN_WAIT = 4  # seconds
    RETRY_MAX_WAIT = 10  # seconds

    def __init__(self, api_key: str, base_url: str):
        """
        Initialize connector with API credentials

        Args:
            api_key: API authentication key
            base_url: Base URL for API endpoints (trailing slash will be removed)
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')  # Remove trailing slash if present

        # Initialize HTTP session with authentication
        self.session = requests.Session()
        self.session.headers.update(self._get_auth_headers())

        # Configure structured logging
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Return authentication headers for API

        Must be implemented by subclasses to provide API-specific auth

        Returns:
            Dictionary of HTTP headers for authentication

        Example:
            {"X-API-Key": self.api_key}
            {"Authorization": f"Bearer {self.api_key}"}
        """
        pass

    @abstractmethod
    def fetch_indicators(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Fetch threat indicators from source

        Must be implemented by subclasses to parse API-specific responses

        Args:
            since: Only fetch indicators updated after this timestamp

        Returns:
            List of indicator dictionaries in standardized format:
            {
                "source": "otx",
                "indicator_value": "1.2.3.4",
                "indicator_type": "IPv4",
                "confidence": 75,
                "tags": ["malware"],
                "ingested_at": "2024-01-01T12:00:00Z",
                "raw_metadata": {...}
            }
        """
        pass

    @retry(
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_exponential(
            multiplier=RETRY_MULTIPLIER,
            min=RETRY_MIN_WAIT,
            max=RETRY_MAX_WAIT
        ),
        retry=retry_if_exception(_should_retry_exception),
        reraise=True
    )
    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """
        Make API request with automatic retry logic

        Retries on transient failures:
        - Connection errors
        - Timeouts
        - HTTP 5xx errors

        Does NOT retry on:
        - HTTP 4xx errors (client errors like bad requests)

        Args:
            endpoint: API endpoint path (appended to base_url)
            params: Optional query parameters

        Returns:
            Parsed JSON response

        Raises:
            requests.RequestException: On request failure after max retries
        """
        # Build full URL, handling leading slashes
        endpoint = endpoint.lstrip('/')
        url = f"{self.base_url}/{endpoint}"

        self.logger.debug(f"Request: GET {url}", extra={"params": params})

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.DEFAULT_TIMEOUT
            )

            # Raise exception for 4xx/5xx status codes
            response.raise_for_status()

            self.logger.debug(f"Response: {response.status_code} from {url}")

            return response.json()

        except requests.exceptions.HTTPError as e:
            # Don't retry on client errors (4xx)
            if e.response is not None and e.response.status_code < 500:
                self.logger.error(f"Client error: {url} - {e.response.status_code}")
                raise
            # Retry on server errors (5xx)
            if e.response is not None:
                self.logger.warning(f"Server error (will retry): {url} - {e.response.status_code}")
            raise

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {url} - {str(e)}")
            raise
