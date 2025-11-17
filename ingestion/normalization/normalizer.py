"""
Indicator Normalizer

Normalizes indicators from different threat intelligence sources to a common schema
"""
from typing import Dict
from datetime import datetime, timezone
import re


class IndicatorNormalizer:
    """
    Normalize indicators from different sources to common schema

    Supports normalization from:
    - AlienVault OTX
    - AbuseIPDB
    - URLhaus
    """

    # Indicator type detection patterns
    INDICATOR_TYPES = {
        "IPv4": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
        "IPv6": r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$",
        "domain": r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
        "URL": r"^https?://",
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA256": r"^[a-fA-F0-9]{64}$"
    }

    # TLP to confidence score mapping
    TLP_CONFIDENCE_MAP = {
        "red": 90,
        "amber": 70,
        "green": 50,
        "white": 30,
        "unknown": 40
    }

    # URLhaus status to confidence mapping
    URLHAUS_STATUS_CONFIDENCE = {
        "online": 80,
        "offline": 50,
        "unknown": 40
    }

    @staticmethod
    def _get_current_timestamp() -> str:
        """
        Get current UTC timestamp in ISO format with Z suffix

        Returns:
            ISO formatted timestamp string with Z suffix
        """
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    def detect_type(self, value: str) -> str:
        """
        Detect indicator type from value using regex patterns

        Args:
            value: Indicator value to analyze

        Returns:
            Detected type (IPv4, IPv6, domain, URL, MD5, SHA256, or Unknown)
        """
        if not value:
            return "Unknown"

        for ioc_type, pattern in self.INDICATOR_TYPES.items():
            if re.match(pattern, value, re.IGNORECASE):
                return ioc_type

        return "Unknown"

    def normalize(self, raw_indicator: Dict) -> Dict:
        """
        Convert raw indicator to normalized schema

        Args:
            raw_indicator: Raw indicator from ingestion

        Returns:
            Normalized indicator dictionary

        Raises:
            ValueError: If source is unknown
            KeyError: If required fields are missing
        """
        source = raw_indicator["source"]

        if source == "otx":
            return self._normalize_otx(raw_indicator)
        elif source == "abuseipdb":
            return self._normalize_abuseipdb(raw_indicator)
        elif source == "urlhaus":
            return self._normalize_urlhaus(raw_indicator)
        else:
            raise ValueError(f"Unknown source: {source}")

    def _normalize_otx(self, raw: Dict) -> Dict:
        """
        Normalize OTX indicator

        Args:
            raw: Raw OTX indicator

        Returns:
            Normalized indicator
        """
        metadata = raw.get("raw_metadata", {})
        tlp = metadata.get("tlp", "unknown")

        normalized = {
            "id": f"norm_{raw['source']}_{raw['indicator_value']}",
            "indicator_value": raw["indicator_value"],
            "indicator_type": self.detect_type(raw["indicator_value"]),
            "confidence_score": self.TLP_CONFIDENCE_MAP.get(tlp.lower(), 40),
            "first_seen": raw["ingested_at"],
            "last_seen": raw["ingested_at"],
            "sources": [{
                "name": "otx",
                "pulse_id": metadata.get("pulse_id"),
                "pulse_name": metadata.get("pulse_name"),
                "tags": metadata.get("tags", []),
                "description": metadata.get("description", "")
            }],
            "normalized_at": self._get_current_timestamp()
        }

        return normalized

    def _normalize_abuseipdb(self, raw: Dict) -> Dict:
        """
        Normalize AbuseIPDB indicator

        Args:
            raw: Raw AbuseIPDB indicator

        Returns:
            Normalized indicator
        """
        metadata = raw.get("raw_metadata", {})

        # AbuseIPDB provides confidence score directly
        confidence = raw.get("confidence", metadata.get("abuse_confidence_score", 50))

        normalized = {
            "id": f"norm_{raw['source']}_{raw['indicator_value']}",
            "indicator_value": raw["indicator_value"],
            "indicator_type": self.detect_type(raw["indicator_value"]),
            "confidence_score": confidence,
            "first_seen": raw["ingested_at"],
            "last_seen": raw["ingested_at"],
            "sources": [{
                "name": "abuseipdb",
                "abuse_confidence_score": metadata.get("abuse_confidence_score"),
                "total_reports": metadata.get("total_reports", 0),
                "last_reported_at": metadata.get("last_reported_at")
            }],
            "normalized_at": self._get_current_timestamp()
        }

        return normalized

    def _normalize_urlhaus(self, raw: Dict) -> Dict:
        """
        Normalize URLhaus indicator

        Args:
            raw: Raw URLhaus indicator

        Returns:
            Normalized indicator
        """
        metadata = raw.get("raw_metadata", {})
        url_status = metadata.get("url_status", "unknown")

        # Map URL status to confidence
        confidence = self.URLHAUS_STATUS_CONFIDENCE.get(url_status.lower(), 40)

        normalized = {
            "id": f"norm_{raw['source']}_{raw['indicator_value']}",
            "indicator_value": raw["indicator_value"],
            "indicator_type": self.detect_type(raw["indicator_value"]),
            "confidence_score": confidence,
            "first_seen": raw["ingested_at"],
            "last_seen": raw["ingested_at"],
            "sources": [{
                "name": "urlhaus",
                "url_status": url_status,
                "threat": metadata.get("threat"),
                "tags": metadata.get("tags", [])
            }],
            "normalized_at": self._get_current_timestamp()
        }

        return normalized
