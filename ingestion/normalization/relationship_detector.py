"""
Indicator Relationship Detector

Detects relationships between threat intelligence indicators
"""
from typing import Dict, List, Optional
from urllib.parse import urlparse
from ipaddress import ip_address, AddressValueError
import re


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL

    Args:
        url: URL string

    Returns:
        Domain name or None if URL contains IP or is invalid
    """
    try:
        parsed = urlparse(url)

        # Check if it's a valid URL with scheme
        if not parsed.scheme or not parsed.netloc:
            return None

        # Get hostname (removes port if present)
        hostname = parsed.hostname

        if not hostname:
            return None

        # Check if hostname is an IP address using ipaddress module
        try:
            ip_address(hostname)
            # It's a valid IP address, not a domain
            return None
        except (AddressValueError, ValueError):
            # Not a valid IP, so it's a domain
            return hostname

    except Exception:
        return None


def extract_ip_from_url(url: str) -> Optional[str]:
    """
    Extract IP address from URL

    Args:
        url: URL string

    Returns:
        IP address or None if URL contains domain or is invalid
    """
    try:
        parsed = urlparse(url)

        # Check if it's a valid URL with scheme
        if not parsed.scheme or not parsed.netloc:
            return None

        # Get hostname (removes port if present)
        hostname = parsed.hostname

        if not hostname:
            return None

        # Check if hostname is a valid IP address using ipaddress module
        try:
            ip_address(hostname)
            # It's a valid IP address
            return hostname
        except (AddressValueError, ValueError):
            # Not a valid IP, it's a domain
            return None

    except Exception:
        return None


def extract_parent_domain(domain: str) -> Optional[str]:
    """
    Extract parent domain from subdomain

    Args:
        domain: Domain name

    Returns:
        Parent domain or None if this is a TLD+1 domain
    """
    # Known multi-part TLDs
    MULTI_PART_TLDS = {
        'co.uk', 'co.in', 'co.jp', 'co.kr', 'co.nz', 'co.za',
        'com.au', 'com.br', 'com.cn', 'com.mx', 'com.tw',
        'ac.uk', 'gov.uk', 'org.uk', 'net.uk',
        'edu.au', 'gov.au', 'org.au'
    }

    parts = domain.split('.')

    # Need at least 3 parts to have a parent (e.g., sub.domain.com)
    if len(parts) < 3:
        return None

    # Check if this is a known multi-part TLD
    # e.g., "example.co.uk" has parts ['example', 'co', 'uk']
    # The TLD is 'co.uk', so "example.co.uk" is TLD+1 (no parent)
    potential_tld = '.'.join(parts[-2:])
    if potential_tld in MULTI_PART_TLDS:
        # This is TLD+1 for a multi-part TLD
        # e.g., "example.co.uk" - no parent
        if len(parts) == 3:
            return None
        # e.g., "sub.example.co.uk" - parent is "example.co.uk"
        return '.'.join(parts[1:])

    # For regular TLDs (e.g., .com, .org)
    # "sub.example.com" → parent is "example.com"
    # "example.com" → no parent (TLD+1)
    return '.'.join(parts[1:])


class RelationshipDetector:
    """
    Detect relationships between threat intelligence indicators

    Relationships include:
    - URL contains domain
    - URL contains IP
    - Subdomain → parent domain
    - Indicators part of same campaign/pulse
    """

    def detect_relationships(self, indicator: Dict) -> List[Dict]:
        """
        Detect all relationships for an indicator

        Args:
            indicator: Normalized indicator dictionary

        Returns:
            List of relationship dictionaries
        """
        relationships = []

        indicator_type = indicator.get("indicator_type")
        indicator_value = indicator.get("indicator_value")

        # Detect URL → domain/IP relationships
        if indicator_type == "URL":
            # Check for domain
            domain = extract_domain_from_url(indicator_value)
            if domain:
                relationships.append({
                    "type": "contains_domain",
                    "target_value": domain,
                    "target_type": "domain"
                })

            # Check for IP
            ip = extract_ip_from_url(indicator_value)
            if ip:
                relationships.append({
                    "type": "contains_ip",
                    "target_value": ip,
                    "target_type": "IPv4"
                })

        # Detect subdomain → parent domain relationship
        if indicator_type == "domain":
            parent = extract_parent_domain(indicator_value)
            if parent:
                relationships.append({
                    "type": "subdomain_of",
                    "target_value": parent,
                    "target_type": "domain"
                })

        # Detect campaign relationships from sources
        sources = indicator.get("sources", [])
        for source in sources:
            # OTX pulse/campaign
            if "pulse_id" in source:
                relationships.append({
                    "type": "part_of_campaign",
                    "campaign_id": source["pulse_id"],
                    "campaign_name": source.get("pulse_name", "Unknown"),
                    "source": source.get("name", "unknown")
                })

        return relationships
