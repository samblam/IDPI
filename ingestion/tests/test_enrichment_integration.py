"""
Integration Tests for AI Enrichment Pipeline

Tests the complete flow: Deduplicated Indicator → AI Enrichment → Storage
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import json

from enrichment.mitre_validator import MITREValidator
from enrichment.enrichment_engine import ThreatEnrichmentEngine
from functions.enrichment_function import process_enrichment, is_recently_enriched


@pytest.mark.integration
class TestEnrichmentPipeline:
    """Test complete enrichment pipeline end-to-end"""

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    async def test_full_enrichment_flow(self, mock_get_secret, mock_openai_class):
        """Test complete flow from indicator to enriched output"""
        mock_get_secret.return_value = "test-key"

        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "classification": "malware",
            "threat_actor": "APT28",
            "campaign": "Snake Campaign",
            "mitre_ttps": ["T1566.001", "T1071.001", "T1486"],
            "severity": "Critical",
            "recommended_actions": [
                "Block all traffic to/from this domain",
                "Alert SOC team immediately",
                "Scan all systems for indicators of compromise"
            ]
        })
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 500
        mock_response.usage.prompt_tokens = 300
        mock_response.usage.completion_tokens = 200

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai_class.return_value = mock_client

        # Real enrichment engine (not mocked)
        engine = ThreatEnrichmentEngine()
        engine.client = mock_client

        # Deduplicated indicator (input)
        indicator = {
            "indicator_value": "evil.example.com",
            "indicator_type": "domain",
            "confidence_score": 95,
            "source_count": 3,
            "sources": [
                {
                    "name": "otx",
                    "pulse_id": "abc123",
                    "tags": ["malware", "botnet", "c2"],
                    "description": "Known command and control server"
                },
                {
                    "name": "abuseipdb",
                    "total_reports": 42
                },
                {
                    "name": "urlhaus",
                    "url_status": "online",
                    "threat": "malware_download"
                }
            ]
        }

        # Enrich
        result = await engine.enrich_indicator(indicator)

        # Verify enrichment structure
        assert "enrichment" in result
        assert "enriched_at" in result
        assert "enrichment_cost" in result

        # Verify enrichment content
        enrichment = result["enrichment"]
        assert enrichment["classification"] == "malware"
        assert enrichment["threat_actor"] == "APT28"
        assert enrichment["severity"] == "Critical"
        assert len(enrichment["mitre_ttps"]) == 3
        assert "T1566.001" in enrichment["mitre_ttps"]
        assert len(enrichment["recommended_actions"]) == 3

        # Verify MITRE validation occurred
        assert "mitre_validation" in enrichment
        assert enrichment["mitre_validation"]["valid_count"] == 3
        assert enrichment["mitre_validation"]["original_count"] == 3

        # Verify cost tracking
        assert result["enrichment_cost"]["tokens_used"] == 500
        assert result["enrichment_cost"]["estimated_cost_usd"] > 0

        # Verify original data preserved
        assert result["indicator_value"] == "evil.example.com"
        assert result["confidence_score"] == 95
        assert result["source_count"] == 3

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    async def test_enrichment_with_invalid_mitre_ttps(self, mock_get_secret, mock_openai_class):
        """Test enrichment filters invalid MITRE TTPs"""
        mock_get_secret.return_value = "test-key"

        # Mock OpenAI response with invalid TTPs
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "classification": "phishing",
            "threat_actor": None,
            "campaign": None,
            "mitre_ttps": [
                "T1566.001",  # Valid
                "T9999",      # Invalid
                "INVALID",    # Invalid
                "T1071.001"   # Valid
            ],
            "severity": "High",
            "recommended_actions": ["Block sender", "Report to security team"]
        })
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 300
        mock_response.usage.prompt_tokens = 200
        mock_response.usage.completion_tokens = 100

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai_class.return_value = mock_client

        engine = ThreatEnrichmentEngine()
        engine.client = mock_client

        indicator = {
            "indicator_value": "phishing.com",
            "indicator_type": "domain",
            "confidence_score": 85,
            "source_count": 1,
            "sources": [{"name": "otx", "tags": ["phishing"]}]
        }

        result = await engine.enrich_indicator(indicator)

        # Verify invalid TTPs were filtered
        enrichment = result["enrichment"]
        assert len(enrichment["mitre_ttps"]) == 2
        assert "T1566.001" in enrichment["mitre_ttps"]
        assert "T1071.001" in enrichment["mitre_ttps"]
        assert "T9999" not in enrichment["mitre_ttps"]
        assert "INVALID" not in enrichment["mitre_ttps"]

        # Verify validation metadata
        assert enrichment["mitre_validation"]["original_count"] == 4
        assert enrichment["mitre_validation"]["valid_count"] == 2
        assert "T9999" in enrichment["mitre_validation"]["filtered"]
        assert "INVALID" in enrichment["mitre_validation"]["filtered"]

    @patch('functions.enrichment_function.CosmosClient')
    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    async def test_change_feed_to_enrichment_flow(self, mock_get_secret, mock_openai_class, mock_cosmos_class):
        """Test complete flow from change feed trigger to storage"""
        mock_get_secret.return_value = "test-key"

        # Mock OpenAI
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "classification": "c2",
            "threat_actor": None,
            "campaign": None,
            "mitre_ttps": ["T1071.001", "T1095"],
            "severity": "High",
            "recommended_actions": ["Block IP", "Monitor network traffic"]
        })
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 400
        mock_response.usage.prompt_tokens = 250
        mock_response.usage.completion_tokens = 150

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai_class.return_value = mock_client

        # Mock Cosmos DB
        mock_cosmos = Mock()
        mock_cosmos_class.return_value = mock_cosmos

        # Simulate change feed document
        doc = {
            "indicator_value": "192.168.1.1",
            "indicator_type": "IPv4",
            "confidence_score": 88,
            "source_count": 2,
            "sources": [
                {"name": "otx", "tags": ["c2"]},
                {"name": "abuseipdb", "total_reports": 25}
            ]
        }

        mock_doc_list = MagicMock()
        mock_doc_list.__iter__ = Mock(return_value=iter([doc]))
        mock_doc_list.__len__ = Mock(return_value=1)

        # Process through enrichment function
        await process_enrichment(mock_doc_list)

        # Verify Cosmos upsert was called
        mock_cosmos.upsert_item.assert_called_once()

        # Get the enriched document that was stored
        call_args = mock_cosmos.upsert_item.call_args
        container = call_args[0][0]
        enriched_doc = call_args[0][1]

        # Verify correct container
        assert container == "enriched_indicators"

        # Verify enriched document structure
        assert enriched_doc["indicator_value"] == "192.168.1.1"
        assert enriched_doc["enrichment"]["classification"] == "c2"
        assert enriched_doc["enrichment"]["severity"] == "High"
        assert "enriched_at" in enriched_doc
        assert "enrichment_cost" in enriched_doc


@pytest.mark.integration
class TestMITREValidatorIntegration:
    """Test MITRE validator with real technique IDs"""

    def test_validates_common_attack_patterns(self):
        """Test validation of common attack patterns"""
        # Common phishing techniques
        assert MITREValidator.validate("T1566") is True
        assert MITREValidator.validate("T1566.001") is True  # Spearphishing Attachment
        assert MITREValidator.validate("T1566.002") is True  # Spearphishing Link

        # Common malware techniques
        assert MITREValidator.validate("T1486") is True  # Data Encrypted for Impact
        assert MITREValidator.validate("T1059.001") is True  # PowerShell
        assert MITREValidator.validate("T1027") is True  # Obfuscated Files

        # Common C2 techniques
        assert MITREValidator.validate("T1071.001") is True  # Web Protocols
        assert MITREValidator.validate("T1095") is True  # Non-Application Layer Protocol

    def test_filters_mixed_valid_invalid(self):
        """Test filtering mix of valid and invalid techniques"""
        techniques = [
            "T1566.001",  # Valid: Spearphishing Attachment
            "T1071.001",  # Valid: Web Protocols
            "T9999",      # Invalid
            "T1486",      # Valid: Data Encrypted for Impact
            "FAKE123",    # Invalid
            "T1059.003"   # Valid: Windows Command Shell
        ]

        filtered = MITREValidator.filter_valid(techniques)

        assert len(filtered) == 4
        assert "T1566.001" in filtered
        assert "T1071.001" in filtered
        assert "T1486" in filtered
        assert "T1059.003" in filtered
        assert "T9999" not in filtered
        assert "FAKE123" not in filtered


@pytest.mark.integration
class TestEnrichmentErrorHandling:
    """Test error handling in enrichment pipeline"""

    def test_is_recently_enriched_handles_invalid_timestamp(self):
        """Test graceful handling of invalid timestamp format"""
        indicator = {
            "enriched_at": "invalid-timestamp"
        }

        # Should not crash, should return False
        result = is_recently_enriched(indicator)
        assert result is False

    def test_is_recently_enriched_handles_missing_timezone(self):
        """Test handling of timestamp without timezone info"""
        indicator = {
            "enriched_at": "2024-01-01T10:00:00"  # No Z or timezone
        }

        # Should handle gracefully
        result = is_recently_enriched(indicator)
        # Result depends on implementation, but should not crash
        assert isinstance(result, bool)

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    async def test_enrichment_handles_missing_optional_fields(self, mock_get_secret, mock_openai_class):
        """Test enrichment with minimal indicator data"""
        mock_get_secret.return_value = "test-key"

        # Mock minimal OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "classification": "unknown",
            "threat_actor": None,
            "campaign": None,
            "mitre_ttps": [],
            "severity": "Low",
            "recommended_actions": ["Manual analysis recommended"]
        })
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 100
        mock_response.usage.prompt_tokens = 60
        mock_response.usage.completion_tokens = 40

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai_class.return_value = mock_client

        engine = ThreatEnrichmentEngine()
        engine.client = mock_client

        # Minimal indicator
        indicator = {
            "indicator_value": "test.com",
            "indicator_type": "domain",
            "confidence_score": 75,
            "source_count": 1,
            "sources": []  # Empty sources
        }

        # Should not crash
        result = await engine.enrich_indicator(indicator)

        assert "enrichment" in result
        assert result["enrichment"]["classification"] == "unknown"
        assert result["enrichment"]["severity"] == "Low"
