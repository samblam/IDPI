"""
HTTP-Triggered Azure Function for Manual/Backfill Ingestion

Allows manual triggering of ingestion for specific sources or time ranges
"""
import logging
import os
import json
from datetime import datetime
from typing import Optional, List, Dict

import azure.functions as func

from connectors.otx_connector import OTXConnector
from connectors.abuseipdb_connector import AbuseIPDBConnector
from connectors.urlhaus_connector import URLhausConnector
from storage.cosmos_client import CosmosClient
from utils.schema_validator import SchemaValidator
from models.raw_indicator import RawIndicator


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    HTTP-triggered function for manual ingestion

    Query parameters:
        - source: Specific source to fetch from (otx, abuseipdb, urlhaus) or 'all'
        - since: ISO8601 timestamp to fetch indicators modified after

    Returns:
        JSON response with ingestion statistics
    """
    logging.info('HTTP trigger function processed a request.')

    # Parse parameters
    source_param = req.params.get('source', 'all')
    since_param = req.params.get('since')

    # Parse since parameter
    since = None
    if since_param:
        try:
            since = datetime.fromisoformat(since_param.replace('Z', '+00:00'))
        except ValueError:
            return func.HttpResponse(
                json.dumps({
                    'error': 'Invalid since parameter. Use ISO8601 format.'
                }),
                status_code=400,
                mimetype='application/json'
            )

    # Initialize clients
    cosmos_client = CosmosClient()
    validator = SchemaValidator()

    # Get sources to process
    try:
        sources = get_sources_for_request(source_param)
    except ValueError as e:
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=400,
            mimetype='application/json'
        )

    # Process sources
    results = {
        'sources_processed': [],
        'ingested_count': 0,
        'failed_sources': []
    }

    for source_name, connector in sources.items():
        try:
            logging.info(f"Fetching from {source_name} (since={since})")

            # Fetch indicators
            indicators = connector.fetch_indicators(since=since)

            # Store indicators
            ingested = store_indicators(indicators, cosmos_client, validator)

            results['sources_processed'].append(source_name)
            results['ingested_count'] += ingested

            logging.info(f"Stored {ingested} indicators from {source_name}")

        except Exception as e:
            logging.error(f"Error processing {source_name}: {e}", exc_info=True)
            results['failed_sources'].append({
                'source': source_name,
                'error': str(e)
            })

    return func.HttpResponse(
        json.dumps(results),
        status_code=200,
        mimetype='application/json'
    )


def get_sources_for_request(source_param: str) -> Dict:
    """
    Get connector instances based on source parameter

    Args:
        source_param: Source name ('otx', 'abuseipdb', 'urlhaus', 'all')

    Returns:
        Dictionary of connector instances

    Raises:
        ValueError: If source parameter is invalid
    """
    valid_sources = ['otx', 'abuseipdb', 'urlhaus', 'all']

    if source_param not in valid_sources:
        raise ValueError(f"Invalid source: {source_param}. Must be one of {valid_sources}")

    sources = {}

    if source_param == 'all' or source_param == 'otx':
        otx_api_key = os.getenv('OTX_API_KEY')
        if otx_api_key:
            sources['otx'] = OTXConnector(api_key=otx_api_key)
        else:
            logging.warning("OTX_API_KEY not configured")

    if source_param == 'all' or source_param == 'abuseipdb':
        abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        if abuseipdb_api_key:
            sources['abuseipdb'] = AbuseIPDBConnector(api_key=abuseipdb_api_key)
        else:
            logging.warning("ABUSEIPDB_API_KEY not configured")

    if source_param == 'all' or source_param == 'urlhaus':
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
        indicators: List of raw indicators
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

    return stored_count
