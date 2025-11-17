"""
Backfill Utility for Data Gap Recovery

Detects and fills gaps in ingested threat intelligence data
"""
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import logging
import time
import os

from connectors.otx_connector import OTXConnector
from connectors.abuseipdb_connector import AbuseIPDBConnector
from connectors.urlhaus_connector import URLhausConnector
from storage.cosmos_client import CosmosClient
from utils.schema_validator import SchemaValidator
from models.raw_indicator import RawIndicator


@dataclass
class BackfillTask:
    """Represents a backfill task for a specific time range"""
    source: str
    start_time: datetime
    end_time: datetime
    status: str  # 'pending', 'in_progress', 'completed', 'failed'
    indicators_fetched: int = 0
    error_message: Optional[str] = None

    def get_duration(self) -> timedelta:
        """Calculate duration of this task"""
        return self.end_time - self.start_time


class BackfillManager:
    """
    Manages backfill operations for threat intelligence data

    Detects gaps, creates backfill tasks, and executes them with rate limiting
    """

    SUPPORTED_SOURCES = ['otx', 'abuseipdb', 'urlhaus']

    def __init__(
        self,
        chunk_hours: int = 24,
        rate_limit_seconds: float = 0.5
    ):
        """
        Initialize backfill manager

        Args:
            chunk_hours: Split large time ranges into chunks of this size
            rate_limit_seconds: Wait time between backfill tasks
        """
        self.chunk_hours = chunk_hours
        self.rate_limit_seconds = rate_limit_seconds
        self.logger = logging.getLogger(self.__class__.__name__)
        self.last_request_time = None

    def create_task(
        self,
        source: str,
        start_time: datetime,
        end_time: datetime
    ):
        """
        Create backfill task(s) for time range

        Large time ranges are automatically split into smaller chunks

        Args:
            source: Source name (otx, abuseipdb, urlhaus)
            start_time: Start of backfill range
            end_time: End of backfill range

        Returns:
            BackfillTask or list of BackfillTask if range was split
        """
        duration = end_time - start_time
        chunk_duration = timedelta(hours=self.chunk_hours)

        # If duration is larger than chunk size, split into multiple tasks
        if duration > chunk_duration:
            tasks = []
            current_start = start_time

            while current_start < end_time:
                current_end = min(current_start + chunk_duration, end_time)

                task = BackfillTask(
                    source=source,
                    start_time=current_start,
                    end_time=current_end,
                    status='pending'
                )
                tasks.append(task)

                current_start = current_end

            self.logger.info(
                f"Split backfill into {len(tasks)} chunks "
                f"for {source} ({start_time} to {end_time})"
            )
            return tasks

        # Single task for small ranges
        return BackfillTask(
            source=source,
            start_time=start_time,
            end_time=end_time,
            status='pending'
        )

    def detect_gaps(
        self,
        indicators: List[Dict],
        expected_interval_minutes: int = 60
    ) -> List[tuple]:
        """
        Detect gaps in ingested data

        Args:
            indicators: List of indicators sorted by ingested_at
            expected_interval_minutes: Expected time between ingestions

        Returns:
            List of (gap_start, gap_end) tuples
        """
        if len(indicators) < 2:
            return []

        gaps = []
        expected_delta = timedelta(minutes=expected_interval_minutes)

        for i in range(len(indicators) - 1):
            current_time = datetime.fromisoformat(
                indicators[i]['ingested_at'].replace('Z', '+00:00')
            )
            next_time = datetime.fromisoformat(
                indicators[i + 1]['ingested_at'].replace('Z', '+00:00')
            )

            time_diff = next_time - current_time

            # If gap is larger than expected interval, record it
            if time_diff > expected_delta * 2:  # Allow some tolerance
                gaps.append((current_time, next_time))
                self.logger.info(
                    f"Detected gap: {current_time} to {next_time} "
                    f"({time_diff.total_seconds() / 3600:.1f} hours)"
                )

        return gaps

    def execute_task(self, task: BackfillTask) -> BackfillTask:
        """
        Execute a backfill task

        Args:
            task: BackfillTask to execute

        Returns:
            Updated task with execution results
        """
        task.status = 'in_progress'
        self.logger.info(
            f"Executing backfill: {task.source} "
            f"from {task.start_time} to {task.end_time}"
        )

        # Apply rate limiting
        self._apply_rate_limit()

        try:
            # Get connector for source
            connector = self._get_connector(task.source)

            if connector is None:
                task.status = 'failed'
                task.error_message = f"Connector not configured for {task.source}"
                return task

            # Fetch indicators
            indicators = connector.fetch_indicators(since=task.start_time)

            # Filter indicators to time range
            filtered = [
                ind for ind in indicators
                if self._in_time_range(ind, task.start_time, task.end_time)
            ]

            # Store indicators
            cosmos_client = CosmosClient()
            validator = SchemaValidator()
            container_name = os.getenv('COSMOS_CONTAINER', 'indicators')

            stored = 0
            for indicator in filtered:
                result = validator.validate(indicator, RawIndicator)
                if result.is_valid:
                    cosmos_client.upsert_item(container_name, indicator)
                    stored += 1

            task.indicators_fetched = stored
            task.status = 'completed'

            self.logger.info(
                f"Backfill completed: {task.source} - "
                f"fetched {len(indicators)}, stored {stored}"
            )

        except Exception as e:
            task.status = 'failed'
            task.error_message = str(e)
            self.logger.error(f"Backfill failed for {task.source}: {e}")

        return task

    def create_tasks_for_all_sources(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[BackfillTask]:
        """
        Create backfill tasks for all supported sources

        Args:
            start_time: Start of backfill range
            end_time: End of backfill range

        Returns:
            List of BackfillTask objects
        """
        all_tasks = []

        for source in self.SUPPORTED_SOURCES:
            tasks = self.create_task(source, start_time, end_time)

            # Handle both single task and list of tasks
            if isinstance(tasks, list):
                all_tasks.extend(tasks)
            else:
                all_tasks.append(tasks)

        return all_tasks

    def get_progress(self, tasks: List[BackfillTask]) -> Dict:
        """
        Get progress statistics for backfill tasks

        Args:
            tasks: List of BackfillTask objects

        Returns:
            Dictionary with progress statistics
        """
        total = len(tasks)
        completed = sum(1 for t in tasks if t.status == 'completed')
        in_progress = sum(1 for t in tasks if t.status == 'in_progress')
        pending = sum(1 for t in tasks if t.status == 'pending')
        failed = sum(1 for t in tasks if t.status == 'failed')

        completion_percentage = (completed / total * 100) if total > 0 else 0

        return {
            'total': total,
            'completed': completed,
            'in_progress': in_progress,
            'pending': pending,
            'failed': failed,
            'completion_percentage': round(completion_percentage, 2)
        }

    def _get_connector(self, source: str):
        """Get connector instance for source"""
        if source == 'otx':
            api_key = os.getenv('OTX_API_KEY')
            return OTXConnector(api_key=api_key) if api_key else None

        elif source == 'abuseipdb':
            api_key = os.getenv('ABUSEIPDB_API_KEY')
            return AbuseIPDBConnector(api_key=api_key) if api_key else None

        elif source == 'urlhaus':
            return URLhausConnector()

        return None

    def _in_time_range(
        self,
        indicator: Dict,
        start_time: datetime,
        end_time: datetime
    ) -> bool:
        """Check if indicator is within time range"""
        try:
            ingested_at = datetime.fromisoformat(
                indicator['ingested_at'].replace('Z', '+00:00')
            )

            # Make start and end timezone-aware if they aren't
            if start_time.tzinfo is None:
                from datetime import timezone
                start_time = start_time.replace(tzinfo=timezone.utc)
            if end_time.tzinfo is None:
                from datetime import timezone
                end_time = end_time.replace(tzinfo=timezone.utc)

            return start_time <= ingested_at <= end_time
        except (KeyError, ValueError):
            return False

    def _apply_rate_limit(self):
        """Apply rate limiting between requests"""
        if self.last_request_time is not None:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.rate_limit_seconds:
                sleep_time = self.rate_limit_seconds - elapsed
                time.sleep(sleep_time)

        self.last_request_time = time.time()
