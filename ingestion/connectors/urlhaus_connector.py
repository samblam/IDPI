"""
URLhaus Connector

Fetches malicious URLs from URLhaus (abuse.ch)
"""
from typing import Dict, List, Optional
from datetime import datetime
from connectors.base import BaseConnector


class URLhausConnector(BaseConnector):
    """
    Connector for URLhaus API

    Fetches recent malicious URLs
    """

    def __init__(self):
        """
        Initialize URLhaus connector

        URLhaus does not require an API key
        """
        super().__init__(
            api_key="",  # No API key needed
            base_url="https://urlhaus-api.abuse.ch/v1"
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Return URLhaus authentication headers

        URLhaus doesn't need authentication

        Returns:
            Empty dictionary
        """
        return {}

    def fetch_indicators(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Fetch recent malicious URLs from URLhaus

        Args:
            since: Not used (URLhaus returns recent URLs)

        Returns:
            List of indicators in standardized format
        """
        endpoint = "urls/recent"
        params = {}

        self.logger.info("Fetching recent URLs from URLhaus")

        try:
            response = self._make_request(endpoint, params)

            if response.get('query_status') != 'ok':
                self.logger.warning(f"URLhaus query not OK: {response.get('query_status')}")
                return []

            urls = response.get('urls', [])
            self.logger.info(f"Retrieved {len(urls)} URLs from URLhaus")

            # Convert to standardized format
            indicators = []
            ingested_at = datetime.utcnow().isoformat() + 'Z'

            for url_data in urls:
                indicator = {
                    'source': 'urlhaus',
                    'indicator_value': url_data.get('url'),
                    'indicator_type': 'URL',
                    'ingested_at': ingested_at,
                    'tags': url_data.get('tags', []),
                    'raw_metadata': {
                        'url_status': url_data.get('url_status'),
                        'threat': url_data.get('threat'),
                        'date_added': url_data.get('date_added')
                    }
                }
                indicators.append(indicator)

            self.logger.info(f"Extracted {len(indicators)} indicators")
            return indicators

        except Exception as e:
            self.logger.error(f"Failed to fetch URLhaus data: {e}")
            raise
