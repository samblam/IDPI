"""
Cosmos DB Change Feed Triggered Function for AI Enrichment

Listens to changes in deduplicated_indicators container and enriches high-confidence indicators
"""
import logging
from typing import Dict
from datetime import datetime, timezone, timedelta

import azure.functions as func

from enrichment.enrichment_engine import ThreatEnrichmentEngine
from storage.cosmos_client import CosmosClient


def is_recently_enriched(indicator: Dict, hours: int = 24) -> bool:
    """
    Check if indicator was enriched recently

    Args:
        indicator: Indicator dictionary
        hours: Number of hours to consider as "recent" (default: 24)

    Returns:
        True if enriched within the time window, False otherwise
    """
    if "enriched_at" not in indicator:
        return False

    try:
        enriched_time = datetime.fromisoformat(
            indicator["enriched_at"].replace('Z', '+00:00')
        )
        age = datetime.now(timezone.utc) - enriched_time

        return age.total_seconds() < (hours * 3600)

    except Exception:
        # If we can't parse the timestamp, assume not recently enriched
        return False


async def process_enrichment(documents: func.DocumentList) -> None:
    """
    Process deduplicated indicators from Cosmos DB change feed

    Triggered when new documents are added to deduplicated_indicators container.
    Only enriches high-confidence indicators (>= 75) to control costs.

    Args:
        documents: List of documents from change feed
    """
    if not documents:
        logging.info("No documents to process")
        return

    logging.info(f"Processing {len(documents)} documents from change feed")

    # Initialize components
    enrichment_engine = ThreatEnrichmentEngine()
    cosmos_client = CosmosClient()

    processed = 0
    skipped_low_confidence = 0
    skipped_recently_enriched = 0
    failed = 0

    for doc in documents:
        try:
            # Convert DocumentList item to dict
            doc_dict = dict(doc)

            indicator_value = doc_dict.get("indicator_value", "unknown")
            confidence_score = doc_dict.get("confidence_score", 0)

            # Skip low-confidence indicators to control costs
            if confidence_score < 75:
                logging.info(
                    f"Skipping low-confidence indicator: {indicator_value} "
                    f"(confidence: {confidence_score})"
                )
                skipped_low_confidence += 1
                continue

            # Skip recently enriched indicators
            if is_recently_enriched(doc_dict):
                logging.info(
                    f"Indicator already enriched recently: {indicator_value}"
                )
                skipped_recently_enriched += 1
                continue

            # Enrich with AI
            logging.info(f"Enriching indicator: {indicator_value}")
            enriched = await enrichment_engine.enrich_indicator(doc_dict)

            # Store in enriched_indicators container
            cosmos_client.upsert_item("enriched_indicators", enriched)

            processed += 1
            logging.info(
                f"Successfully enriched: {enriched['indicator_value']} "
                f"(classification: {enriched['enrichment']['classification']}, "
                f"severity: {enriched['enrichment']['severity']})"
            )

        except Exception as e:
            failed += 1
            logging.error(
                f"Failed to enrich document {doc.get('id', 'unknown')}: {e}",
                exc_info=True
            )
            # Continue processing other documents

    logging.info(
        f"Enrichment complete. Processed: {processed}, "
        f"Skipped (low confidence): {skipped_low_confidence}, "
        f"Skipped (recently enriched): {skipped_recently_enriched}, "
        f"Failed: {failed}"
    )


# Azure Functions entry point (for deployment)
async def main(documents: func.DocumentList) -> None:
    """
    Azure Function entry point for Cosmos DB change feed trigger

    This function is called by Azure Functions runtime when new documents
    are added to the deduplicated_indicators container.

    Args:
        documents: List of documents from change feed
    """
    await process_enrichment(documents)
