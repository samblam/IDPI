"""
Threat Enrichment Engine

AI-powered threat intelligence enrichment using Azure OpenAI
"""
from typing import Dict
from datetime import datetime, timezone
import json
import logging
import os

from openai import AsyncAzureOpenAI

from enrichment.mitre_validator import MITREValidator


def get_secret(secret_name: str) -> str:
    """
    Get secret from environment or Azure Key Vault

    For now, reads from environment variables.
    In production, integrate with Azure Key Vault.

    Args:
        secret_name: Name of the secret

    Returns:
        Secret value
    """
    # Map secret names to environment variables
    secret_map = {
        "OPENAI-API-KEY": "OPENAI_API_KEY",
        "AZURE-OPENAI-KEY": "AZURE_OPENAI_KEY"
    }

    env_var = secret_map.get(secret_name, secret_name.replace("-", "_"))
    value = os.getenv(env_var)

    if not value:
        raise ValueError(f"Secret not found: {secret_name}")

    return value


class ThreatEnrichmentEngine:
    """
    AI-powered threat intelligence enrichment with structured outputs

    Uses Azure OpenAI to analyze indicators and provide:
    - Threat classification
    - MITRE ATT&CK TTP mapping
    - Severity assessment
    - Recommended actions
    """

    def __init__(self):
        """Initialize enrichment engine"""
        # Configure OpenAI client
        api_key = get_secret("OPENAI-API-KEY")
        azure_endpoint = os.getenv("OPENAI_ENDPOINT", "https://api.openai.com/v1")

        self.client = AsyncAzureOpenAI(
            api_key=api_key,
            api_version="2024-10-21",
            azure_endpoint=azure_endpoint
        )

        # Model configuration (configurable via environment)
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-2024-08-06")

        # MITRE validator
        self.mitre_validator = MITREValidator()

        # Cost tracking
        self.total_tokens_used = 0
        self.total_cost = 0.0

        self.logger = logging.getLogger(self.__class__.__name__)

    def _build_context(self, indicator: Dict) -> str:
        """
        Build context string for OpenAI from indicator data

        Args:
            indicator: Indicator dictionary

        Returns:
            Formatted context string
        """
        context_parts = [
            f"Indicator: {indicator['indicator_value']}",
            f"Type: {indicator['indicator_type']}",
            f"Confidence: {indicator['confidence_score']}/100",
            f"Sources: {indicator['source_count']} different threat feeds",
            ""
        ]

        # Add source-specific context
        for source in indicator.get("sources", []):
            context_parts.append(f"From {source['name']}:")

            if source.get("tags"):
                context_parts.append(f"  Tags: {', '.join(source['tags'])}")

            if source.get("description"):
                context_parts.append(f"  Description: {source['description']}")

            context_parts.append("")

        return "\n".join(context_parts)

    async def _call_openai(self, context: str) -> Dict:
        """
        Call OpenAI with structured outputs (JSON mode)

        Args:
            context: Context string describing the indicator

        Returns:
            Structured enrichment data dictionary
        """
        system_prompt = """You are a threat intelligence analyst. Analyze the provided
indicator and its context to determine:

1. Threat Classification: malware, phishing, C2, exfiltration, reconnaissance, etc.
2. Likely Threat Actor: If identifiable, name the APT group or threat actor
3. Campaign Association: If part of a known campaign, identify it
4. MITRE ATT&CK TTPs: Map to specific technique IDs (e.g., T1566.001, T1071.001)
5. Severity Assessment: Critical, High, Medium, Low
6. Recommended Actions: Specific mitigation steps

Respond ONLY with valid JSON using these exact keys: classification, threat_actor,
campaign, mitre_ttps (array of strings), severity, recommended_actions (array of strings)."""

        user_prompt = f"""Analyze this threat indicator:

{context}

Provide structured analysis in JSON format."""

        # Define response format schema for structured outputs
        response_format = {
            "type": "json_schema",
            "json_schema": {
                "name": "threat_enrichment",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "classification": {"type": "string"},
                        "threat_actor": {"type": ["string", "null"]},
                        "campaign": {"type": ["string", "null"]},
                        "mitre_ttps": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["Critical", "High", "Medium", "Low"]
                        },
                        "recommended_actions": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["classification", "severity", "mitre_ttps", "recommended_actions"],
                    "additionalProperties": False
                }
            }
        }

        # Call OpenAI
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format=response_format,
            temperature=0.3,  # Lower temperature for consistent output
            max_tokens=800
        )

        # Track token usage and costs
        usage = response.usage
        self.total_tokens_used += usage.total_tokens

        # GPT-4o pricing (as of 2024): $2.50/1M input, $10/1M output tokens
        input_cost = (usage.prompt_tokens / 1_000_000) * 2.50
        output_cost = (usage.completion_tokens / 1_000_000) * 10.00
        total_cost = input_cost + output_cost
        self.total_cost += total_cost

        self.logger.info(f"OpenAI API call: {usage.total_tokens} tokens, ${total_cost:.4f}")

        # Parse JSON response (guaranteed valid with structured outputs)
        enrichment_data = json.loads(response.choices[0].message.content)

        return enrichment_data

    def _validate_and_clean_enrichment(self, enrichment: Dict) -> Dict:
        """
        Validate and clean enrichment data (including MITRE ATT&CK validation)

        Args:
            enrichment: Raw enrichment data from OpenAI

        Returns:
            Validated and cleaned enrichment dictionary
        """
        try:
            # Validate MITRE ATT&CK technique IDs
            if "mitre_ttps" in enrichment:
                if isinstance(enrichment["mitre_ttps"], list):
                    original_ttps = enrichment["mitre_ttps"]
                    valid_ttps = self.mitre_validator.filter_valid(original_ttps)

                    if len(valid_ttps) < len(original_ttps):
                        invalid = set(original_ttps) - set(valid_ttps)
                        self.logger.warning(f"Filtered invalid MITRE techniques: {invalid}")

                    enrichment["mitre_ttps"] = valid_ttps
                    enrichment["mitre_validation"] = {
                        "original_count": len(original_ttps),
                        "valid_count": len(valid_ttps),
                        "filtered": list(invalid) if len(valid_ttps) < len(original_ttps) else []
                    }
                else:
                    # mitre_ttps is not a list, set to empty list
                    self.logger.warning(f"mitre_ttps is not a list: {type(enrichment['mitre_ttps'])}")
                    enrichment["mitre_ttps"] = []

            # Ensure required fields exist
            required = ["classification", "severity", "recommended_actions"]
            for field in required:
                if field not in enrichment:
                    self.logger.error(f"Missing required field: {field}")
                    enrichment[field] = "unknown" if field != "recommended_actions" else []

            return enrichment

        except Exception as e:
            self.logger.error(f"Enrichment validation failed: {e}", exc_info=True)
            return {
                "classification": "unknown",
                "severity": "Medium",
                "recommended_actions": ["Manual analysis required"],
                "mitre_ttps": [],
                "validation_error": str(e)
            }

    async def enrich_indicator(self, indicator: Dict) -> Dict:
        """
        Enrich indicator with AI analysis

        Args:
            indicator: Deduplicated indicator dictionary

        Returns:
            Enriched indicator with AI analysis added
        """
        # Build context from all sources
        context = self._build_context(indicator)

        # Call OpenAI with structured outputs
        enrichment = await self._call_openai(context)

        # Validate and clean enrichment (includes MITRE validation)
        validated = self._validate_and_clean_enrichment(enrichment)

        # Add enrichment to indicator
        indicator["enrichment"] = validated
        indicator["enriched_at"] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        indicator["enrichment_cost"] = {
            "tokens_used": self.total_tokens_used,
            "estimated_cost_usd": round(self.total_cost, 4)
        }

        return indicator
