"""
Deduplication Engine

Merges duplicate indicators from multiple sources and calculates composite confidence scores
"""
from typing import List, Dict
from datetime import datetime, timedelta
import logging


def calculate_composite_score(scores: List[int]) -> int:
    """
    Calculate composite confidence score from multiple sources

    Higher confidence when multiple sources agree on the same indicator.
    Uses average score as base with a multiplier based on number of sources.

    Args:
        scores: List of confidence scores from different sources

    Returns:
        Composite score (0-100)
    """
    if not scores:
        return 0

    # Calculate base score (average)
    base_score = sum(scores) / len(scores)

    # Boost confidence when multiple sources agree
    # +10% per additional source, capped at +50% (1.5x multiplier)
    source_multiplier = min(1.0 + (len(scores) - 1) * 0.1, 1.5)

    # Calculate final score, capped at 100
    composite = int(base_score * source_multiplier)
    return min(composite, 100)


def merge_duplicates(duplicates: List[Dict]) -> Dict:
    """
    Merge duplicate indicators from multiple sources

    Combines sources, calculates composite confidence, and determines
    earliest/latest sighting times.

    Args:
        duplicates: List of duplicate indicator dictionaries

    Returns:
        Merged indicator dictionary
    """
    if not duplicates:
        raise ValueError("Cannot merge empty list of duplicates")

    # Start with first indicator as base
    merged = duplicates[0].copy()

    # Generate deduplicated ID
    merged["id"] = f"dedup_{merged['indicator_value']}"

    # Combine all sources
    all_sources = []
    for dup in duplicates:
        all_sources.extend(dup["sources"])
    merged["sources"] = all_sources

    # Calculate composite confidence score
    scores = [dup["confidence_score"] for dup in duplicates]
    merged["confidence_score"] = calculate_composite_score(scores)

    # Use earliest first_seen
    merged["first_seen"] = min(dup["first_seen"] for dup in duplicates)

    # Use latest last_seen
    merged["last_seen"] = max(dup["last_seen"] for dup in duplicates)

    # Count unique source names
    unique_sources = set(s["name"] for s in all_sources)
    merged["source_count"] = len(unique_sources)

    return merged


class DeduplicationEngine:
    """
    Engine for deduplicating indicators from multiple sources

    Groups indicators by value and merges duplicates with composite scoring.
    """

    def __init__(self):
        """Initialize deduplication engine"""
        self.logger = logging.getLogger(self.__class__.__name__)

    def group_by_value(self, indicators: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Group indicators by their value

        Args:
            indicators: List of indicator dictionaries

        Returns:
            Dictionary mapping indicator_value to list of indicators
        """
        grouped = {}

        for indicator in indicators:
            value = indicator["indicator_value"]
            if value not in grouped:
                grouped[value] = []
            grouped[value].append(indicator)

        return grouped

    def deduplicate(self, indicators: List[Dict]) -> List[Dict]:
        """
        Deduplicate list of indicators

        Groups by value and merges duplicates.

        Args:
            indicators: List of normalized indicators

        Returns:
            List of deduplicated indicators
        """
        if not indicators:
            return []

        # Group by indicator value
        grouped = self.group_by_value(indicators)

        # Merge each group
        deduplicated = []
        for indicator_value, group in grouped.items():
            merged = merge_duplicates(group)
            deduplicated.append(merged)

        self.logger.info(
            f"Deduplicated {len(indicators)} indicators into {len(deduplicated)} unique indicators"
        )

        return deduplicated

    def deduplicate_from_cosmos(
        self,
        container: str = "normalized_indicators",
        hours_lookback: int = 24
    ) -> List[Dict]:
        """
        Query Cosmos DB and deduplicate indicators

        Queries indicators from the specified time window and deduplicates them.

        Args:
            container: Cosmos DB container name
            hours_lookback: Number of hours to look back

        Returns:
            List of deduplicated indicators
        """
        from storage.cosmos_client import CosmosClient

        cosmos_client = CosmosClient()

        # Calculate cutoff time
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_lookback)
        cutoff_iso = cutoff_time.isoformat() + "Z"

        # Query indicators from time window
        query = """
            SELECT * FROM c
            WHERE c.normalized_at > @cutoff_time
            ORDER BY c.indicator_value
        """

        parameters = [{"name": "@cutoff_time", "value": cutoff_iso}]

        self.logger.info(f"Querying indicators from last {hours_lookback} hours")

        indicators = cosmos_client.query_items(container, query, parameters)

        self.logger.info(f"Retrieved {len(indicators)} indicators from Cosmos DB")

        # Deduplicate
        deduplicated = self.deduplicate(indicators)

        return deduplicated
