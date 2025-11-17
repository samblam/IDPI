"""
OTX (AlienVault Open Threat Exchange) Connector

Fetches threat intelligence from OTX pulses
"""
from typing import Dict, List, Optional
from datetime import datetime
from connectors.base import BaseConnector
import logging


class OTXConnector(BaseConnector):
    """
    Connector for AlienVault OTX API

    Fetches indicators from subscribed pulses
    """

    def __init__(self, api_key: str):
        """
        Initialize OTX connector

        Args:
            api_key: OTX API key
        """
        super().__init__(
            api_key=api_key,
            base_url="https://otx.alienvault.com/api/v1"
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Return OTX authentication headers

        Returns:
            Dictionary with X-OTX-API-Key header
        """
        return {"X-OTX-API-Key": self.api_key}

    def fetch_indicators(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Fetch indicators from OTX pulses

        Args:
            since: Only fetch indicators modified after this timestamp

        Returns:
            List of indicators in standardized format
        """
        endpoint = "pulses/subscribed"
        params = {}

        if since:
            # OTX expects ISO format without timezone
            params["modified_since"] = since.strftime("%Y-%m-%dT%H:%M:%S")

        self.logger.info(f"Fetching OTX indicators (since={since})")

        try:
            response = self._make_request(endpoint, params)

            # Extract pulses from response
            pulses = response.get('results', [])
            self.logger.info(f"Retrieved {len(pulses)} pulses from OTX")

            # Convert to standardized indicator format
            indicators = []
            for pulse in pulses:
                indicators.extend(self._parse_pulse(pulse))

            self.logger.info(f"Extracted {len(indicators)} indicators from pulses")
            return indicators

        except Exception as e:
            self.logger.error(f"Failed to fetch OTX indicators: {e}")
            raise

    def _parse_pulse(self, pulse: Dict) -> List[Dict]:
        """
        Parse OTX pulse into standardized indicators

        Args:
            pulse: OTX pulse dictionary

        Returns:
            List of standardized indicators
        """
        pulse_indicators = pulse.get('indicators', [])

        if not pulse_indicators:
            return []

        # Extract pulse metadata
        pulse_metadata = {
            'pulse_id': pulse.get('id'),
            'pulse_name': pulse.get('name'),
            'tlp': pulse.get('TLP', 'unknown'),
            'tags': pulse.get('tags', []),
            'description': pulse.get('description', '')
        }

        indicators = []
        ingested_at = datetime.utcnow().isoformat() + 'Z'

        for indicator in pulse_indicators:
            standardized = {
                'source': 'otx',
                'indicator_value': indicator.get('indicator'),
                'indicator_type': indicator.get('type'),
                'ingested_at': ingested_at,
                'raw_metadata': {
                    **pulse_metadata,
                    'indicator_description': indicator.get('description', '')
                }
            }

            indicators.append(standardized)

        return indicators
