"""
Timer-Triggered Azure Function for Periodic Threat Intel Ingestion

Runs on schedule (e.g., every 15 minutes) to fetch threat intel from all sources
"""
import logging
import os
from datetime import datetime
from typing import List, Dict

import azure.functions as func

from connectors.otx_connector import OTXConnector
from connectors.abuseipdb_connector import AbuseIPDBConnector
from connectors.urlhaus_connector import URLhausConnector
from storage.cosmos_client import CosmosClient
from utils.schema_validator import SchemaValidator
from models.raw_indicator import RawIndicator


def main(mytimer: func.TimerRequest) -> None:
    """
    Timer-triggered function to ingest threat intelligence

    Fetches indicators from all configured sources and stores in Cosmos DB

    Args:
        mytimer: Timer trigger object
    """
    if mytimer.past_due:
        logging.warning('Timer is past due!')

    logging.info('Timer trigger function started')

    # Initialize storage
    cosmos_client = CosmosClient()
    validator = SchemaValidator()

    # Get all configured sources
    sources = get_configured_sources()

    total_ingested = 0

    for source_name, connector in sources.items():
        try:
            logging.info(f"Fetching indicators from {source_name}")

            # Fetch indicators
            indicators = connector.fetch_indicators()

            logging.info(f"Fetched {len(indicators)} indicators from {source_name}")

            # Validate and store
            ingested = store_indicators(indicators, cosmos_client, validator)
            total_ingested += ingested

            logging.info(f"Stored {ingested} valid indicators from {source_name}")

        except Exception as e:
            logging.error(f"Error fetching from {source_name}: {e}", exc_info=True)
            # Continue with other sources even if one fails

    logging.info(f"Timer trigger completed. Total ingested: {total_ingested}")


def get_configured_sources() -> Dict:
    """
    Get all configured threat intel sources

    Returns:
        Dictionary mapping source name to connector instance
    """
    sources = {}

    # OTX (requires API key)
    otx_api_key = os.getenv('OTX_API_KEY')
    if otx_api_key:
        sources['otx'] = OTXConnector(api_key=otx_api_key)
    else:
        logging.warning("OTX_API_KEY not configured, skipping OTX")

    # AbuseIPDB (requires API key)
    abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
    if abuseipdb_api_key:
        sources['abuseipdb'] = AbuseIPDBConnector(api_key=abuseipdb_api_key)
    else:
        logging.warning("ABUSEIPDB_API_KEY not configured, skipping AbuseIPDB")

    # URLhaus (no API key required)
    sources['urlhaus'] = URLhausConnector()

    return sources


def store_indicators(
    indicators: List[Dict],
    cosmos_client: CosmosClient,
    validator: SchemaValidator
) -> int:
    """
    Validate and store indicators in Cosmos DB

    Args:
        indicators: List of raw indicators from connector
        cosmos_client: Cosmos DB client
        validator: Schema validator

    Returns:
        Number of successfully stored indicators
    """
    stored_count = 0
    container_name = os.getenv('COSMOS_CONTAINER', 'indicators')

    for indicator in indicators:
        try:
            # Validate indicator
            result = validator.validate(indicator, RawIndicator)

            if result.is_valid:
                # Store in Cosmos DB
                cosmos_client.upsert_item(container_name, indicator)
                stored_count += 1
            else:
                logging.warning(f"Invalid indicator: {result.errors}")

        except Exception as e:
            logging.error(f"Error storing indicator: {e}")
            # Continue with other indicators

    return stored_count
