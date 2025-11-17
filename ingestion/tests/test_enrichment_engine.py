"""
Tests for Threat Enrichment Engine

Following TDD - Tests written FIRST
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import json

from enrichment.enrichment_engine import ThreatEnrichmentEngine


@pytest.mark.unit
class TestEnrichmentEngineInitialization:
    """Test ThreatEnrichmentEngine initialization"""

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    def test_initialization_with_defaults(self, mock_get_secret, mock_openai_class):
        """Should initialize with default model"""
        mock_get_secret.return_value = "test-api-key"

        engine = ThreatEnrichmentEngine()

        assert engine.model == "gpt-4o-2024-08-06"  # Default model
        assert engine.total_tokens_used == 0
        assert engine.total_cost == 0.0
        assert engine.mitre_validator is not None

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    @patch.dict('os.environ', {'OPENAI_MODEL': 'gpt-4o-mini'})
    def test_initialization_with_custom_model(self, mock_get_secret, mock_openai_class):
        """Should use custom model from environment variable"""
        mock_get_secret.return_value = "test-api-key"

        engine = ThreatEnrichmentEngine()

        assert engine.model == "gpt-4o-mini"

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    @patch.dict('os.environ', {'OPENAI_ENDPOINT': 'https://test.openai.azure.com'})
    def test_initialization_with_endpoint(self, mock_get_secret, mock_openai_class):
        """Should configure Azure endpoint from environment"""
        mock_get_secret.return_value = "test-api-key"

        ThreatEnrichmentEngine()

        # Verify OpenAI client was initialized with correct endpoint
        mock_openai_class.assert_called_once()
        call_kwargs = mock_openai_class.call_args[1]
        assert call_kwargs['azure_endpoint'] == 'https://test.openai.azure.com'


@pytest.mark.unit
class TestBuildContext:
    """Test building context for OpenAI"""

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    def test_build_context_basic_indicator(self, mock_get_secret, mock_openai_class):
        """Should build context from indicator data"""
        mock_get_secret.return_value = "test-key"
        engine = ThreatEnrichmentEngine()

        indicator = {
            "indicator_value": "evil.com",
            "indicator_type": "domain",
            "confidence_score": 85,
            "source_count": 2,
            "sources": [
                {
                    "name": "otx",
                    "tags": ["malware", "botnet"],
                    "description": "Known C2 domain"
                }
            ]
        }

        context = engine._build_context(indicator)

        assert "evil.com" in context
        assert "domain" in context
        assert "85/100" in context
        assert "2 different threat feeds" in context
        assert "otx" in context
        assert "malware" in context
        assert "botnet" in context
        assert "Known C2 domain" in context

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    def test_build_context_multiple_sources(self, mock_get_secret, mock_openai_class):
        """Should include all sources in context"""
        mock_get_secret.return_value = "test-key"
        engine = ThreatEnrichmentEngine()

        indicator = {
            "indicator_value": "1.2.3.4",
            "indicator_type": "IPv4",
            "confidence_score": 90,
            "source_count": 3,
            "sources": [
                {"name": "otx", "tags": ["malware"]},
                {"name": "abuseipdb", "total_reports": 42},
                {"name": "urlhaus", "url_status": "online"}
            ]
        }

        context = engine._build_context(indicator)

        assert "otx" in context
        assert "abuseipdb" in context
        assert "urlhaus" in context

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    def test_build_context_handles_missing_fields(self, mock_get_secret, mock_openai_class):
        """Should handle missing optional fields gracefully"""
        mock_get_secret.return_value = "test-key"
        engine = ThreatEnrichmentEngine()

        indicator = {
            "indicator_value": "test.com",
            "indicator_type": "domain",
            "confidence_score": 50,
            "source_count": 1,
            "sources": [{"name": "test"}]  # No tags or description
        }

        context = engine._build_context(indicator)

        assert "test.com" in context
        # Should not crash, context should be buildable


@pytest.mark.unit
@pytest.mark.asyncio
class TestCallOpenAI:
    """Test OpenAI API integration"""

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    async def test_call_openai_returns_structured_output(self, mock_get_secret, mock_openai_class):
        """Should call OpenAI and return structured JSON"""
        mock_get_secret.return_value = "test-key"

        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "classification": "malware",
            "threat_actor": "APT28",
            "campaign": "Snake Campaign",
            "mitre_ttps": ["T1566.001", "T1071.001"],
            "severity": "High",
            "recommended_actions": ["Block domain", "Alert SOC"]
        })
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 500
        mock_response.usage.prompt_tokens = 300
        mock_response.usage.completion_tokens = 200

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai_class.return_value = mock_client

        engine = ThreatEnrichmentEngine()
        engine.client = mock_client

        result = await engine._call_openai("Test context")

        assert result["classification"] == "malware"
        assert result["threat_actor"] == "APT28"
        assert result["severity"] == "High"
        assert len(result["mitre_ttps"]) == 2
        assert "T1566.001" in result["mitre_ttps"]

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    async def test_call_openai_tracks_token_usage(self, mock_get_secret, mock_openai_class):
        """Should track token usage and costs"""
        mock_get_secret.return_value = "test-key"

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "classification": "phishing",
            "severity": "Medium",
            "mitre_ttps": [],
            "recommended_actions": []
        })
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 1000
        mock_response.usage.prompt_tokens = 600
        mock_response.usage.completion_tokens = 400

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai_class.return_value = mock_client

        engine = ThreatEnrichmentEngine()
        engine.client = mock_client

        await engine._call_openai("Test context")

        assert engine.total_tokens_used == 1000
        # GPT-4o pricing: $2.50/1M input, $10/1M output
        expected_cost = (600 / 1_000_000) * 2.50 + (400 / 1_000_000) * 10.00
        assert abs(engine.total_cost - expected_cost) < 0.0001

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    async def test_call_openai_uses_structured_outputs(self, mock_get_secret, mock_openai_class):
        """Should use JSON schema for structured outputs"""
        mock_get_secret.return_value = "test-key"

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "classification": "test",
            "severity": "Low",
            "mitre_ttps": [],
            "recommended_actions": []
        })
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 100
        mock_response.usage.prompt_tokens = 50
        mock_response.usage.completion_tokens = 50

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai_class.return_value = mock_client

        engine = ThreatEnrichmentEngine()
        engine.client = mock_client

        await engine._call_openai("Test")

        # Verify response_format was provided
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert "response_format" in call_kwargs
        assert call_kwargs["response_format"]["type"] == "json_schema"


@pytest.mark.unit
class TestValidateAndCleanEnrichment:
    """Test enrichment validation and cleaning"""

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    def test_validate_filters_invalid_mitre_ttps(self, mock_get_secret, mock_openai_class):
        """Should filter out invalid MITRE technique IDs"""
        mock_get_secret.return_value = "test-key"
        engine = ThreatEnrichmentEngine()

        enrichment = {
            "classification": "malware",
            "severity": "High",
            "mitre_ttps": ["T1566", "INVALID", "T1071", "T9999"],
            "recommended_actions": ["Block"]
        }

        result = engine._validate_and_clean_enrichment(enrichment)

        assert result["mitre_ttps"] == ["T1566", "T1071"]
        assert result["mitre_validation"]["original_count"] == 4
        assert result["mitre_validation"]["valid_count"] == 2
        assert "INVALID" in result["mitre_validation"]["filtered"]
        assert "T9999" in result["mitre_validation"]["filtered"]

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    def test_validate_all_valid_mitre_ttps(self, mock_get_secret, mock_openai_class):
        """Should keep all valid MITRE technique IDs"""
        mock_get_secret.return_value = "test-key"
        engine = ThreatEnrichmentEngine()

        enrichment = {
            "classification": "phishing",
            "severity": "Critical",
            "mitre_ttps": ["T1566.001", "T1566.002", "T1071.001"],
            "recommended_actions": ["Alert"]
        }

        result = engine._validate_and_clean_enrichment(enrichment)

        assert result["mitre_ttps"] == ["T1566.001", "T1566.002", "T1071.001"]
        assert result["mitre_validation"]["filtered"] == []

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    def test_validate_handles_missing_required_fields(self, mock_get_secret, mock_openai_class):
        """Should add defaults for missing required fields"""
        mock_get_secret.return_value = "test-key"
        engine = ThreatEnrichmentEngine()

        enrichment = {}  # Empty enrichment

        result = engine._validate_and_clean_enrichment(enrichment)

        assert result["classification"] == "unknown"
        assert result["severity"] == "unknown"
        assert result["recommended_actions"] == []

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    def test_validate_handles_validation_errors(self, mock_get_secret, mock_openai_class):
        """Should handle validation errors gracefully"""
        mock_get_secret.return_value = "test-key"
        engine = ThreatEnrichmentEngine()

        # Enrichment that will cause error (e.g., mitre_ttps is not a list)
        enrichment = {
            "classification": "test",
            "mitre_ttps": "not_a_list"  # Should be a list
        }

        result = engine._validate_and_clean_enrichment(enrichment)

        # Should handle the invalid mitre_ttps gracefully
        assert result["mitre_ttps"] == []  # Fixed to empty list
        assert result["classification"] == "test"  # Preserved


@pytest.mark.unit
@pytest.mark.asyncio
class TestEnrichIndicator:
    """Test full indicator enrichment flow"""

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    async def test_enrich_indicator_end_to_end(self, mock_get_secret, mock_openai_class):
        """Should enrich indicator end-to-end"""
        mock_get_secret.return_value = "test-key"

        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "classification": "malware",
            "threat_actor": "APT28",
            "campaign": None,
            "mitre_ttps": ["T1566", "T1071"],
            "severity": "High",
            "recommended_actions": ["Block domain", "Monitor traffic"]
        })
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 500
        mock_response.usage.prompt_tokens = 300
        mock_response.usage.completion_tokens = 200

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai_class.return_value = mock_client

        engine = ThreatEnrichmentEngine()
        engine.client = mock_client

        indicator = {
            "indicator_value": "evil.com",
            "indicator_type": "domain",
            "confidence_score": 90,
            "source_count": 2,
            "sources": [{"name": "otx", "tags": ["malware"]}]
        }

        result = await engine.enrich_indicator(indicator)

        assert "enrichment" in result
        assert result["enrichment"]["classification"] == "malware"
        assert result["enrichment"]["threat_actor"] == "APT28"
        assert result["enrichment"]["severity"] == "High"
        assert "enriched_at" in result
        assert "enrichment_cost" in result
        assert result["enrichment_cost"]["tokens_used"] == 500

    @patch('enrichment.enrichment_engine.AsyncAzureOpenAI')
    @patch('enrichment.enrichment_engine.get_secret')
    async def test_enrich_indicator_preserves_original_data(self, mock_get_secret, mock_openai_class):
        """Should preserve original indicator data"""
        mock_get_secret.return_value = "test-key"

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "classification": "test",
            "severity": "Low",
            "mitre_ttps": [],
            "recommended_actions": []
        })
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 100
        mock_response.usage.prompt_tokens = 50
        mock_response.usage.completion_tokens = 50

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_openai_class.return_value = mock_client

        engine = ThreatEnrichmentEngine()
        engine.client = mock_client

        indicator = {
            "indicator_value": "test.com",
            "indicator_type": "domain",
            "confidence_score": 50,
            "source_count": 1,
            "sources": []
        }

        result = await engine.enrich_indicator(indicator)

        # Original data should still be present
        assert result["indicator_value"] == "test.com"
        assert result["indicator_type"] == "domain"
        assert result["confidence_score"] == 50
