"""
Tests for Indicator Relationship Detection

Following TDD - Tests written FIRST
"""
import pytest
from normalization.relationship_detector import RelationshipDetector, extract_domain_from_url, extract_ip_from_url


@pytest.mark.unit
class TestDomainExtraction:
    """Test extracting domains from URLs"""

    def test_extract_domain_from_http_url(self):
        """Should extract domain from HTTP URL"""
        url = "http://evil.com/malware.exe"
        domain = extract_domain_from_url(url)
        assert domain == "evil.com"

    def test_extract_domain_from_https_url(self):
        """Should extract domain from HTTPS URL"""
        url = "https://malicious.org/phishing"
        domain = extract_domain_from_url(url)
        assert domain == "malicious.org"

    def test_extract_domain_with_subdomain(self):
        """Should extract full domain including subdomain"""
        url = "https://www.evil.com/path"
        domain = extract_domain_from_url(url)
        assert domain == "www.evil.com"

    def test_extract_domain_with_port(self):
        """Should extract domain when port is specified"""
        url = "http://evil.com:8080/path"
        domain = extract_domain_from_url(url)
        assert domain == "evil.com"

    def test_extract_domain_with_path_and_query(self):
        """Should extract domain ignoring path and query parameters"""
        url = "https://evil.com/path?param=value&foo=bar"
        domain = extract_domain_from_url(url)
        assert domain == "evil.com"

    def test_extract_domain_returns_none_for_ip_url(self):
        """Should return None if URL contains IP instead of domain"""
        url = "http://192.168.1.1/malware"
        domain = extract_domain_from_url(url)
        assert domain is None

    def test_extract_domain_returns_none_for_non_url(self):
        """Should return None for non-URL strings"""
        assert extract_domain_from_url("not-a-url") is None
        assert extract_domain_from_url("evil.com") is None  # Domain but not URL


@pytest.mark.unit
class TestIPExtraction:
    """Test extracting IPs from URLs"""

    def test_extract_ip_from_url_with_ipv4(self):
        """Should extract IPv4 from URL"""
        url = "http://192.168.1.1/malware.exe"
        ip = extract_ip_from_url(url)
        assert ip == "192.168.1.1"

    def test_extract_ip_with_port(self):
        """Should extract IP when port is specified"""
        url = "http://10.0.0.1:8080/path"
        ip = extract_ip_from_url(url)
        assert ip == "10.0.0.1"

    def test_extract_ip_returns_none_for_domain_url(self):
        """Should return None if URL contains domain instead of IP"""
        url = "http://evil.com/malware"
        ip = extract_ip_from_url(url)
        assert ip is None

    def test_extract_ip_returns_none_for_non_url(self):
        """Should return None for non-URL strings"""
        assert extract_ip_from_url("192.168.1.1") is None  # IP but not URL
        assert extract_ip_from_url("not-a-url") is None


@pytest.mark.unit
class TestRelationshipDetector:
    """Test relationship detection for indicators"""

    def test_initialization(self):
        """Should initialize relationship detector"""
        detector = RelationshipDetector()
        assert detector is not None

    def test_detect_url_to_domain_relationship(self):
        """Should detect relationship between URL and domain"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "https://evil.com/malware.exe",
            "indicator_type": "URL"
        }

        relationships = detector.detect_relationships(indicator)

        assert len(relationships) == 1
        assert relationships[0]["type"] == "contains_domain"
        assert relationships[0]["target_value"] == "evil.com"
        assert relationships[0]["target_type"] == "domain"

    def test_detect_url_to_ip_relationship(self):
        """Should detect relationship between URL and IP"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "http://192.168.1.1/malware",
            "indicator_type": "URL"
        }

        relationships = detector.detect_relationships(indicator)

        assert len(relationships) == 1
        assert relationships[0]["type"] == "contains_ip"
        assert relationships[0]["target_value"] == "192.168.1.1"
        assert relationships[0]["target_type"] == "IPv4"

    def test_no_relationships_for_ip(self):
        """Should return empty list for standalone IP"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "192.168.1.1",
            "indicator_type": "IPv4"
        }

        relationships = detector.detect_relationships(indicator)
        assert relationships == []

    def test_no_relationships_for_domain(self):
        """Should return empty list for standalone domain"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "evil.com",
            "indicator_type": "domain"
        }

        relationships = detector.detect_relationships(indicator)
        assert relationships == []

    def test_no_relationships_for_hash(self):
        """Should return empty list for hash"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "5d41402abc4b2a76b9719d911017c592",
            "indicator_type": "MD5"
        }

        relationships = detector.detect_relationships(indicator)
        assert relationships == []

    def test_campaign_relationship_from_sources(self):
        """Should detect campaign relationship from source metadata"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "evil.com",
            "indicator_type": "domain",
            "sources": [{
                "name": "otx",
                "pulse_id": "campaign_xyz",
                "pulse_name": "APT28 Campaign"
            }]
        }

        relationships = detector.detect_relationships(indicator)

        assert len(relationships) == 1
        assert relationships[0]["type"] == "part_of_campaign"
        assert relationships[0]["campaign_id"] == "campaign_xyz"
        assert relationships[0]["campaign_name"] == "APT28 Campaign"

    def test_multiple_campaigns_from_multiple_sources(self):
        """Should detect multiple campaign relationships"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "evil.com",
            "indicator_type": "domain",
            "sources": [
                {
                    "name": "otx",
                    "pulse_id": "campaign_1",
                    "pulse_name": "Campaign 1"
                },
                {
                    "name": "otx",
                    "pulse_id": "campaign_2",
                    "pulse_name": "Campaign 2"
                }
            ]
        }

        relationships = detector.detect_relationships(indicator)

        assert len(relationships) == 2
        campaign_ids = {r["campaign_id"] for r in relationships if r["type"] == "part_of_campaign"}
        assert campaign_ids == {"campaign_1", "campaign_2"}

    def test_combined_relationships(self):
        """Should detect both URL and campaign relationships"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "https://evil.com/malware",
            "indicator_type": "URL",
            "sources": [{
                "name": "otx",
                "pulse_id": "campaign_abc",
                "pulse_name": "Malware Campaign"
            }]
        }

        relationships = detector.detect_relationships(indicator)

        assert len(relationships) == 2

        # Check for URL → domain relationship
        url_rels = [r for r in relationships if r["type"] == "contains_domain"]
        assert len(url_rels) == 1
        assert url_rels[0]["target_value"] == "evil.com"

        # Check for campaign relationship
        campaign_rels = [r for r in relationships if r["type"] == "part_of_campaign"]
        assert len(campaign_rels) == 1
        assert campaign_rels[0]["campaign_id"] == "campaign_abc"

    def test_handles_missing_sources_field(self):
        """Should handle indicators without sources field"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "evil.com",
            "indicator_type": "domain"
            # No 'sources' field
        }

        relationships = detector.detect_relationships(indicator)
        assert relationships == []

    def test_handles_sources_without_campaign_info(self):
        """Should handle sources without pulse/campaign info"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "evil.com",
            "indicator_type": "domain",
            "sources": [{
                "name": "abuseipdb",
                "total_reports": 50
                # No pulse_id or campaign info
            }]
        }

        relationships = detector.detect_relationships(indicator)
        assert relationships == []

    def test_subdomain_parent_relationship(self):
        """Should detect parent domain relationship for subdomains"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "sub.evil.com",
            "indicator_type": "domain"
        }

        relationships = detector.detect_relationships(indicator)

        assert len(relationships) == 1
        assert relationships[0]["type"] == "subdomain_of"
        assert relationships[0]["target_value"] == "evil.com"
        assert relationships[0]["target_type"] == "domain"

    def test_no_parent_for_simple_domain(self):
        """Should not detect parent for simple (non-subdomain) domains"""
        detector = RelationshipDetector()

        indicator = {
            "indicator_value": "evil.com",
            "indicator_type": "domain"
        }

        relationships = detector.detect_relationships(indicator)
        # Should only have relationships if there are campaigns
        # With no sources, should be empty
        assert relationships == []

    def test_no_parent_for_tld_plus_one(self):
        """Should not detect parent for TLD+1 domains like co.uk"""
        detector = RelationshipDetector()

        # These are valid domains that shouldn't have parent relationships
        test_cases = [
            "example.co.uk",  # TLD is co.uk
            "example.com",    # Simple domain
            "test.org"        # Simple domain
        ]

        for domain_value in test_cases:
            indicator = {
                "indicator_value": domain_value,
                "indicator_type": "domain"
            }

            relationships = detector.detect_relationships(indicator)

            # Filter to only subdomain relationships
            subdomain_rels = [r for r in relationships if r["type"] == "subdomain_of"]
            assert len(subdomain_rels) == 0, f"{domain_value} should not have parent"
