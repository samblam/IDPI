"""
Cosmos DB Change Feed Triggered Function for Indicator Normalization

Listens to changes in raw_indicators container and normalizes them
"""
import logging
from typing import List

import azure.functions as func

from normalization.normalizer import IndicatorNormalizer
from storage.cosmos_client import CosmosClient


def process_normalization(documents: func.DocumentList) -> None:
    """
    Process raw indicators from Cosmos DB change feed

    Triggered when new documents are added to raw_indicators container.
    Normalizes indicators and stores them in normalized_indicators container.

    Args:
        documents: List of documents from change feed
    """
    if not documents:
        logging.info("No documents to process")
        return

    logging.info(f"Processing {len(documents)} documents from change feed")

    # Initialize components
    normalizer = IndicatorNormalizer()
    cosmos_client = CosmosClient()

    processed = 0
    failed = 0

    for doc in documents:
        try:
            # Convert DocumentList item to dict
            doc_dict = dict(doc)

            logging.info(f"Normalizing indicator: {doc_dict.get('indicator_value')}")

            # Normalize the indicator
            normalized = normalizer.normalize(doc_dict)

            # Store in normalized_indicators container
            cosmos_client.upsert_item("normalized_indicators", normalized)

            processed += 1
            logging.info(f"Successfully normalized: {normalized['indicator_value']}")

        except Exception as e:
            failed += 1
            logging.error(
                f"Failed to normalize document {doc.get('id', 'unknown')}: {e}",
                exc_info=True
            )
            # Continue processing other documents

    logging.info(
        f"Normalization complete. Processed: {processed}, Failed: {failed}"
    )


# Azure Functions entry point (for deployment)
def main(documents: func.DocumentList) -> None:
    """
    Azure Function entry point for Cosmos DB change feed trigger

    This function is called by Azure Functions runtime when new documents
    are added to the raw_indicators container.

    Args:
        documents: List of documents from change feed
    """
    process_normalization(documents)
