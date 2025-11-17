"""
AbuseIPDB Connector

Fetches IP reputation data from AbuseIPDB
"""
from typing import Dict, List, Optional
from datetime import datetime
from connectors.base import BaseConnector


class AbuseIPDBConnector(BaseConnector):
    """
    Connector for AbuseIPDB API

    Fetches reported malicious IPs
    """

    def __init__(self, api_key: str):
        """
        Initialize AbuseIPDB connector

        Args:
            api_key: AbuseIPDB API key
        """
        super().__init__(
            api_key=api_key,
            base_url="https://api.abuseipdb.com/api/v2"
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Return AbuseIPDB authentication headers

        Returns:
            Dictionary with Key header
        """
        return {"Key": self.api_key}

    def fetch_indicators(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Fetch blacklisted IPs from AbuseIPDB

        Args:
            since: Only fetch IPs reported after this timestamp

        Returns:
            List of indicators in standardized format
        """
        endpoint = "blacklist"
        params = {"confidenceMinimum": 75}  # Only high-confidence reports

        self.logger.info("Fetching AbuseIPDB blacklist")

        try:
            response = self._make_request(endpoint, params)

            ips = response.get('data', [])
            self.logger.info(f"Retrieved {len(ips)} IPs from AbuseIPDB")

            # Convert to standardized format
            indicators = []
            ingested_at = datetime.utcnow().isoformat() + 'Z'

            for ip_data in ips:
                indicator = {
                    'source': 'abuseipdb',
                    'indicator_value': ip_data.get('ipAddress'),
                    'indicator_type': 'IPv4',  # AbuseIPDB is IPv4/IPv6
                    'confidence': ip_data.get('abuseConfidenceScore'),
                    'ingested_at': ingested_at,
                    'raw_metadata': {
                        'total_reports': ip_data.get('totalReports', 0),
                        'last_reported': ip_data.get('lastReportedAt'),
                        'country_code': ip_data.get('countryCode'),
                        'is_whitelisted': ip_data.get('isWhitelisted', False)
                    }
                }
                indicators.append(indicator)

            self.logger.info(f"Extracted {len(indicators)} indicators")
            return indicators

        except Exception as e:
            self.logger.error(f"Failed to fetch AbuseIPDB data: {e}")
            raise
