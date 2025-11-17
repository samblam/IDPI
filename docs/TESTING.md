# ThreatStream Testing Strategy

Comprehensive testing methodology, coverage reports, and best practices.

## Table of Contents

1. [Testing Philosophy](#testing-philosophy)
2. [Test Structure](#test-structure)
3. [Running Tests](#running-tests)
4. [Test Coverage](#test-coverage)
5. [Testing Patterns](#testing-patterns)
6. [Continuous Integration](#continuous-integration)

---

## Testing Philosophy

### Test-Driven Development (TDD)

All code in ThreatStream was developed using strict TDD methodology:

```
1. RED: Write failing test FIRST
   ↓
2. GREEN: Implement minimum code to pass
   ↓
3. REFACTOR: Improve code while keeping tests passing
   ↓
4. Repeat
```

**Benefits**:
- ✅ 200+ tests, 92% average coverage
- ✅ Regression prevention
- ✅ Better API design (testability drives design)
- ✅ Living documentation (tests show usage)

### Test Pyramid

```
         ┌─────────────┐
        /   Integration \   (10% - 30 tests)
       /─────────────────\
      /   Unit Tests      \  (90% - 170+ tests)
     /─────────────────────\
    ───────────────────────────
```

**Distribution**:
- **Unit Tests (90%)**: Fast, isolated, high coverage
- **Integration Tests (10%)**: End-to-end workflows
- **No E2E Tests**: Serverless architecture makes full E2E expensive and slow

---

## Test Structure

### Directory Layout

```
ingestion/tests/
├── __init__.py
│
├── fixtures/                    # Shared test data
│   ├── mock_otx_response.json
│   ├── mock_abuseipdb_response.json
│   └── sample_indicators.json
│
├── conftest.py                  # Pytest fixtures
│
├── test_connectors.py           # External API connectors
├── test_base_connector.py
├── test_otx_connector.py
├── test_abuseipdb_connector.py
├── test_urlhaus_connector.py
│
├── test_cosmos_client.py        # Cosmos DB client
│
├── test_models.py               # Pydantic models
├── test_schema_validator.py
│
├── test_normalizer.py           # Normalization logic
├── test_deduplicator.py
├── test_relationship_detector.py
│
├── test_enrichment_engine.py    # AI enrichment
├── test_mitre_validator.py
│
├── test_api_key_manager.py      # API services
├── test_cache_service.py
├── test_query_service.py
│
├── test_api_integration.py      # End-to-end API tests
│
├── test_normalization_integration.py
├── test_enrichment_integration.py
│
└── test_azure_functions.py      # Function triggers
```

---

## Running Tests

### All Tests

```bash
cd ingestion

# Run all tests with verbose output
pytest -v

# Run all tests with coverage
pytest --cov=. --cov-report=html

# Run all tests in parallel (faster)
pytest -n auto
```

### Specific Test Categories

```bash
# Unit tests only
pytest -m unit -v

# Integration tests only
pytest -m integration -v

# Specific module
pytest tests/test_enrichment_engine.py -v

# Specific test class
pytest tests/test_enrichment_engine.py::TestThreatEnrichmentEngine -v

# Specific test case
pytest tests/test_enrichment_engine.py::TestThreatEnrichmentEngine::test_enrich_indicator_returns_valid_result -v
```

### Watch Mode (Development)

```bash
# Install pytest-watch
pip install pytest-watch

# Run tests on file changes
ptw -- -v
```

### Coverage Reports

```bash
# Generate HTML coverage report
pytest --cov=. --cov-report=html

# Open in browser (macOS)
open htmlcov/index.html

# Generate terminal report
pytest --cov=. --cov-report=term-missing

# Generate XML report (for CI)
pytest --cov=. --cov-report=xml
```

---

## Test Coverage

### Current Coverage by Module

| Module | Lines | Tests | Coverage |
|--------|-------|-------|----------|
| **Data Ingestion** ||||
| `connectors/base.py` | 52 | 13 | 95% |
| `connectors/otx_connector.py` | 38 | 8 | 95% |
| `connectors/abuseipdb_connector.py` | 26 | 6 | 92% |
| `storage/cosmos_client.py` | 82 | 12 | 94% |
| **Normalization** ||||
| `normalization/normalizer.py` | 42 | 15 | 98% |
| `normalization/deduplicator.py` | 71 | 18 | 97% |
| `normalization/relationship_detector.py` | 66 | 16 | 96% |
| **AI Enrichment** ||||
| `enrichment/enrichment_engine.py` | 78 | 15 | 92% |
| `enrichment/mitre_validator.py` | 16 | 25 | 100% |
| **Query API** ||||
| `api/services/api_key_manager.py` | 41 | 16 | 93% |
| `api/services/cache_service.py` | 109 | 21 | 86% |
| `api/services/query_service.py` | 111 | 15 | 85% |
| **Total** | **1,630+** | **200+** | **92%** |

### Coverage Goals

- **Minimum**: 80% coverage (enforced in CI)
- **Target**: 90% coverage
- **Current**: 92% average

### Uncovered Lines

Intentionally uncovered code:
- Exception handlers for external service failures (hard to simulate)
- Azure Functions runtime initialization (requires deployed environment)
- Cosmos DB emulator connection fallback

---

## Testing Patterns

### 1. Mocking External Dependencies

All external services (APIs, databases) are mocked in unit tests.

#### Example: Mocking OTX API

```python
@patch('connectors.otx_connector.requests.Session.get')
def test_fetch_indicators_returns_valid_data(self, mock_get):
    """Should fetch and parse OTX indicators"""
    # Arrange
    mock_response = Mock()
    mock_response.json.return_value = {
        "results": [
            {
                "id": "pulse123",
                "name": "Malware Campaign",
                "indicators": [
                    {"indicator": "evil.com", "type": "domain"}
                ]
            }
        ]
    }
    mock_response.raise_for_status = Mock()
    mock_get.return_value = mock_response

    # Act
    connector = OTXConnector(api_key="test-key")
    indicators = connector.fetch_indicators()

    # Assert
    assert len(indicators) == 1
    assert indicators[0]["indicator_value"] == "evil.com"
    assert indicators[0]["source"] == "otx"
```

**Pattern**: Arrange-Act-Assert (AAA)

---

### 2. Async Testing

All async functions tested with pytest-asyncio.

#### Example: Testing Async Enrichment

```python
@pytest.mark.asyncio
async def test_enrich_indicator_returns_valid_result(self, mock_openai_client):
    """Should enrich indicator with GPT-4o analysis"""
    # Arrange
    mock_response = AsyncMock()
    mock_response.choices = [
        Mock(message=Mock(content='{"classification": "Malware"}'))
    ]
    mock_openai_client.return_value.chat.completions.create = AsyncMock(
        return_value=mock_response
    )

    engine = ThreatEnrichmentEngine()
    indicator = {"indicator_value": "evil.com", "indicator_type": "domain"}

    # Act
    result = await engine.enrich_indicator(indicator)

    # Assert
    assert result["enrichment"]["classification"] == "Malware"
```

**Configuration** (pytest.ini):
```ini
[pytest]
asyncio_mode = auto
```

---

### 3. Fixture Reuse (conftest.py)

Common test data and mocks defined in conftest.py.

```python
# conftest.py
import pytest
from unittest.mock import Mock, AsyncMock

@pytest.fixture
def sample_indicator():
    """Sample threat indicator for testing"""
    return {
        "id": "test-indicator",
        "indicator_value": "evil.com",
        "indicator_type": "domain",
        "confidence_score": 85,
        "sources": [{"name": "otx", "confidence": 85}]
    }

@pytest.fixture
def mock_cosmos_client():
    """Mock Cosmos DB client"""
    mock = Mock()
    mock.get_item = Mock(return_value=None)
    mock.upsert_item = Mock(return_value={})
    mock.query_items = Mock(return_value=[])
    return mock

@pytest.fixture
def mock_redis_client():
    """Mock Redis client"""
    mock = Mock()
    mock.get = Mock(return_value=None)
    mock.setex = Mock(return_value=True)
    mock.delete = Mock(return_value=1)
    return mock
```

**Usage**:
```python
def test_something(sample_indicator, mock_cosmos_client):
    # Fixtures automatically injected
    result = process(sample_indicator)
    assert result is not None
```

---

### 4. Parameterized Tests

Test multiple scenarios with one test function.

```python
@pytest.mark.parametrize("indicator_type,expected_valid", [
    ("domain", True),
    ("IPv4", True),
    ("IPv6", True),
    ("url", True),
    ("email", True),
    ("invalid", False),
    ("", False),
])
def test_indicator_type_validation(indicator_type, expected_valid):
    """Should validate indicator types correctly"""
    result = validate_indicator_type(indicator_type)
    assert result == expected_valid
```

**Benefits**:
- Reduces code duplication
- Clear test matrix
- Easier to add new cases

---

### 5. Integration Testing

End-to-end workflows tested with real component integration (but still mocked external services).

```python
@pytest.mark.integration
async def test_full_normalization_workflow(self, mock_cosmos_client):
    """Should normalize, deduplicate, and detect relationships"""
    # Arrange: Multiple indicators from different sources
    raw_indicators = [
        {"source": "otx", "indicator_value": "evil.com", "confidence": 80},
        {"source": "abuseipdb", "indicator_value": "evil.com", "confidence": 90},
    ]

    # Act: Run through full normalization pipeline
    normalizer = Normalizer()
    deduplicator = Deduplicator(mock_cosmos_client)
    detector = RelationshipDetector()

    normalized = [normalizer.normalize(ind) for ind in raw_indicators]
    deduplicated = deduplicator.deduplicate(normalized)
    relationships = detector.detect_relationships(deduplicated)

    # Assert: Verify full pipeline results
    assert len(deduplicated) == 1  # Merged into one
    assert deduplicated[0]["confidence_score"] == 85  # Weighted average
    assert deduplicated[0]["source_count"] == 2
```

---

### 6. Test Markers

Organize tests with pytest markers.

```python
# Mark test as unit test
@pytest.mark.unit
def test_normalize_domain():
    ...

# Mark test as integration test
@pytest.mark.integration
def test_full_pipeline():
    ...

# Mark test as slow (skip in development)
@pytest.mark.slow
def test_large_dataset():
    ...

# Skip test conditionally
@pytest.mark.skipif(not OPENAI_API_KEY, reason="OpenAI key not configured")
def test_real_openai_call():
    ...
```

**Run specific markers**:
```bash
pytest -m unit        # Unit tests only
pytest -m integration # Integration tests only
pytest -m "not slow"  # Skip slow tests
```

---

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          cd ingestion
          pip install -r requirements.txt

      - name: Run tests with coverage
        run: |
          cd ingestion
          pytest --cov=. --cov-report=xml --cov-report=term

      - name: Check coverage threshold
        run: |
          cd ingestion
          pytest --cov=. --cov-fail-under=80

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./ingestion/coverage.xml
```

### Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Install git hooks
pre-commit install
```

**.pre-commit-config.yaml**:
```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.1.0
    hooks:
      - id: black

  - repo: https://github.com/PyCQA/flake8
    rev: 6.0.0
    hooks:
      - id: flake8

  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: pytest
        language: system
        pass_filenames: false
        always_run: true
        args: ['-v', '--cov=.', '--cov-fail-under=80']
```

---

## Best Practices

### 1. Test Naming Convention

```python
# ✅ GOOD: Descriptive test names
def test_normalize_domain_converts_to_lowercase():
    ...

def test_deduplicate_merges_indicators_from_multiple_sources():
    ...

def test_enrich_indicator_returns_valid_mitre_ttps():
    ...

# ❌ BAD: Vague test names
def test_normalize():
    ...

def test_dedup():
    ...

def test_enrich():
    ...
```

### 2. One Assertion Per Test

```python
# ✅ GOOD: Single responsibility
def test_normalize_converts_to_lowercase(self):
    result = normalizer.normalize({"indicator_value": "EVIL.COM"})
    assert result["indicator_value"] == "evil.com"

def test_normalize_strips_whitespace(self):
    result = normalizer.normalize({"indicator_value": " evil.com "})
    assert result["indicator_value"] == "evil.com"

# ❌ BAD: Multiple assertions
def test_normalize(self):
    result = normalizer.normalize({"indicator_value": "EVIL.COM"})
    assert result["indicator_value"] == "evil.com"
    assert result["confidence_score"] > 0
    assert result["sources"] is not None
```

### 3. Arrange-Act-Assert Pattern

```python
def test_example(self):
    # Arrange: Set up test data
    indicator = {"indicator_value": "evil.com"}

    # Act: Execute the code under test
    result = process(indicator)

    # Assert: Verify the result
    assert result["status"] == "success"
```

### 4. Test Independence

```python
# ✅ GOOD: Each test is independent
def test_first():
    data = {"value": 1}
    result = process(data)
    assert result == 1

def test_second():
    data = {"value": 2}
    result = process(data)
    assert result == 2

# ❌ BAD: Tests depend on each other
class_variable = None

def test_first():
    global class_variable
    class_variable = process({"value": 1})
    assert class_variable == 1

def test_second():
    # Fails if test_first doesn't run first
    assert class_variable == 1
```

### 5. Mock at the Boundary

```python
# ✅ GOOD: Mock external service
@patch('requests.Session.get')
def test_fetch_data(self, mock_get):
    mock_get.return_value.json.return_value = {"data": "test"}
    result = fetch_from_api()
    assert result["data"] == "test"

# ❌ BAD: Mock internal function
@patch('my_module.process_data')
def test_fetch_data(self, mock_process):
    # Not testing anything meaningful
    result = fetch_from_api()
```

---

## Debugging Failed Tests

### Verbose Output

```bash
# Show print statements
pytest -v -s

# Show local variables on failure
pytest --showlocals

# Drop into debugger on failure
pytest --pdb
```

### Run Specific Failed Test

```bash
# Re-run only failed tests
pytest --lf

# Re-run failed tests first
pytest --ff
```

### Debugging Tips

1. **Use `pytest -s`** to see print statements
2. **Add `import pdb; pdb.set_trace()`** for breakpoints
3. **Check fixture scope** if tests interfere
4. **Verify mocks** are patching correct path
5. **Check test order** if tests pass individually but fail together

---

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [pytest-cov](https://pytest-cov.readthedocs.io/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
- [Testing Best Practices](https://docs.python-guide.org/writing/tests/)

---

## Summary

**ThreatStream Testing Strategy**:

- ✅ 200+ tests across all modules
- ✅ 92% average code coverage
- ✅ TDD methodology throughout
- ✅ Fast feedback loop (<10 seconds for full suite)
- ✅ CI/CD integration
- ✅ High confidence in refactoring

Testing is not just about finding bugs—it's about **confidence in change**.
