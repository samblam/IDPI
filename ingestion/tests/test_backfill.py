"""
Tests for Backfill Utility

Following TDD - Tests written FIRST
"""
import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from utils.backfill import BackfillManager, BackfillTask


@pytest.mark.unit
class TestBackfillManager:
    """Test backfill manager"""

    def test_initialization(self):
        """Should initialize backfill manager"""
        manager = BackfillManager()
        assert manager is not None

    def test_create_backfill_task(self):
        """Should create backfill task with time range"""
        manager = BackfillManager()

        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)

        task = manager.create_task(
            source='otx',
            start_time=start,
            end_time=end
        )

        assert task.source == 'otx'
        assert task.start_time == start
        assert task.end_time == end
        assert task.status == 'pending'

    def test_split_large_time_range_into_chunks(self):
        """Should split large time ranges into smaller chunks"""
        manager = BackfillManager(chunk_hours=24)

        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 5)  # 4 days = 4 chunks

        tasks = manager.create_task(
            source='otx',
            start_time=start,
            end_time=end
        )

        # Should create multiple tasks for large ranges
        assert isinstance(tasks, list)
        assert len(tasks) == 4

    def test_detect_gaps_in_data(self):
        """Should detect gaps in ingested data"""
        manager = BackfillManager()

        # Simulate indicators with gap
        indicators = [
            {'ingested_at': '2024-01-01T10:00:00Z'},
            {'ingested_at': '2024-01-01T11:00:00Z'},
            # GAP: Missing 12:00 - 14:00
            {'ingested_at': '2024-01-01T15:00:00Z'},
        ]

        gaps = manager.detect_gaps(
            indicators,
            expected_interval_minutes=60
        )

        assert len(gaps) > 0
        # Gap should be detected between 11:00 and 15:00

    @patch('utils.backfill.OTXConnector')
    @patch('utils.backfill.CosmosClient')
    def test_execute_backfill_task(self, mock_cosmos, mock_otx):
        """Should execute backfill task"""
        # Setup connector mock with timestamp in task range
        task_start = datetime(2024, 1, 1)
        task_end = datetime(2024, 1, 2)

        mock_connector = Mock()
        mock_connector.fetch_indicators.return_value = [
            {
                'source': 'otx',
                'indicator_value': '1.2.3.4',
                'indicator_type': 'IPv4',
                'ingested_at': '2024-01-01T12:00:00Z'  # Within task range
            }
        ]
        mock_otx.return_value = mock_connector

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        manager = BackfillManager()

        task = BackfillTask(
            source='otx',
            start_time=task_start,
            end_time=task_end,
            status='pending'
        )

        with patch.dict('os.environ', {'OTX_API_KEY': 'test-key'}):
            result = manager.execute_task(task)

        assert result.status == 'completed'
        assert result.indicators_fetched == 1
        mock_connector.fetch_indicators.assert_called_once()

    @patch('utils.backfill.OTXConnector')
    @patch('utils.backfill.CosmosClient')
    def test_handles_backfill_errors(self, mock_cosmos, mock_otx):
        """Should handle errors during backfill gracefully"""
        # Setup connector to fail
        mock_connector = Mock()
        mock_connector.fetch_indicators.side_effect = Exception("API Error")
        mock_otx.return_value = mock_connector

        mock_cosmos_instance = Mock()
        mock_cosmos.return_value = mock_cosmos_instance

        manager = BackfillManager()

        task = BackfillTask(
            source='otx',
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 2),
            status='pending'
        )

        with patch.dict('os.environ', {'OTX_API_KEY': 'test-key'}):
            result = manager.execute_task(task)

        assert result.status == 'failed'
        assert result.error_message is not None

    def test_get_backfill_progress(self):
        """Should track backfill progress"""
        manager = BackfillManager()

        tasks = [
            BackfillTask('otx', datetime(2024, 1, 1), datetime(2024, 1, 2), status='completed'),
            BackfillTask('otx', datetime(2024, 1, 2), datetime(2024, 1, 3), status='in_progress'),
            BackfillTask('otx', datetime(2024, 1, 3), datetime(2024, 1, 4), status='pending'),
            BackfillTask('otx', datetime(2024, 1, 4), datetime(2024, 1, 5), status='pending'),
        ]

        progress = manager.get_progress(tasks)

        assert progress['total'] == 4
        assert progress['completed'] == 1
        assert progress['in_progress'] == 1
        assert progress['pending'] == 2
        assert progress['completion_percentage'] == 25.0

    def test_rate_limiting_between_tasks(self):
        """Should respect rate limits between backfill tasks"""
        manager = BackfillManager(rate_limit_seconds=1)

        task1 = BackfillTask('otx', datetime(2024, 1, 1), datetime(2024, 1, 2), 'pending')
        task2 = BackfillTask('otx', datetime(2024, 1, 2), datetime(2024, 1, 3), 'pending')

        with patch.dict('os.environ', {'OTX_API_KEY': 'test-key'}):
            with patch('utils.backfill.OTXConnector') as mock_otx:
                with patch('utils.backfill.CosmosClient'):
                    with patch('time.sleep') as mock_sleep:
                        mock_connector = Mock()
                        mock_connector.fetch_indicators.return_value = []
                        mock_otx.return_value = mock_connector

                        manager.execute_task(task1)
                        manager.execute_task(task2)

                        # Should sleep between tasks for rate limiting
                        mock_sleep.assert_called()

    def test_backfill_all_sources(self):
        """Should support backfilling all sources at once"""
        manager = BackfillManager()

        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)

        tasks = manager.create_tasks_for_all_sources(
            start_time=start,
            end_time=end
        )

        # Should create tasks for all known sources
        assert len(tasks) >= 3  # otx, abuseipdb, urlhaus
        sources = {t.source for t in tasks}
        assert 'otx' in sources
        assert 'abuseipdb' in sources
        assert 'urlhaus' in sources


@pytest.mark.unit
class TestBackfillTask:
    """Test backfill task model"""

    def test_task_creation(self):
        """Should create backfill task"""
        task = BackfillTask(
            source='otx',
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 2),
            status='pending'
        )

        assert task.source == 'otx'
        assert task.status == 'pending'

    def test_task_duration_calculation(self):
        """Should calculate task duration"""
        task = BackfillTask(
            source='otx',
            start_time=datetime(2024, 1, 1, 10, 0),
            end_time=datetime(2024, 1, 1, 14, 0),
            status='pending'
        )

        duration = task.get_duration()
        assert duration == timedelta(hours=4)

    def test_task_status_transitions(self):
        """Should transition task status correctly"""
        task = BackfillTask(
            source='otx',
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 2),
            status='pending'
        )

        assert task.status == 'pending'

        task.status = 'in_progress'
        assert task.status == 'in_progress'

        task.status = 'completed'
        assert task.status == 'completed'
