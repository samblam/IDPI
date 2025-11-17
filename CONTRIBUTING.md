# Contributing to ThreatStream Intelligence Pipeline

Thank you for your interest in contributing! This is a portfolio project, but contributions are welcome.

## Development Setup

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/IDPI.git
cd IDPI
```

### 2. Set up Python environment

```bash
cd ingestion
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Set up local services

Using Docker Compose (recommended):
```bash
# From project root
docker-compose up -d cosmos-emulator redis
```

Or manually:
- Install Cosmos DB Emulator (Windows) or use Docker
- Install Redis locally or via Docker

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

Required environment variables:
- `COSMOS_ENDPOINT` - Cosmos DB endpoint
- `COSMOS_KEY` - Cosmos DB key
- `OPENAI_ENDPOINT` - Azure OpenAI endpoint
- `OPENAI_API_KEY` - Azure OpenAI key
- `REDIS_HOST` - Redis host
- `REDIS_PORT` - Redis port

### 5. Run tests

```bash
# Python tests - Ingestion
cd ingestion
pytest tests/ --cov=. --cov-report=term-missing

# Python tests - API
cd api
pytest tests/ --cov=. --cov-report=term-missing

# Dashboard tests
cd dashboard
npm install
npm test
```

## Making Changes

### 1. Create a feature branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make your changes

Follow the coding standards below.

### 3. Write tests

- Unit tests for all business logic
- Integration tests for API endpoints
- Maintain >80% code coverage
- Mock external services (Azure OpenAI, threat intel APIs)

### 4. Run linters

```bash
# Python
cd ingestion
flake8 .
black --check .
mypy .

# TypeScript/JavaScript
cd dashboard
npm run lint
```

### 5. Commit your changes

Use conventional commit messages:

```bash
git commit -m "feat: Add new feature description"
git commit -m "fix: Fix bug description"
git commit -m "docs: Update documentation"
```

Commit types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code formatting (no logic changes)
- `refactor:` - Code refactoring
- `test:` - Adding tests
- `chore:` - Maintenance tasks

### 6. Push and create PR

```bash
git push origin feature/your-feature-name
```

Then open a pull request on GitHub.

## Coding Standards

### Python

- Follow PEP 8 style guide
- Use type hints for all function parameters and return values
- Write docstrings for all public functions (Google style)
- Maximum line length: 100 characters
- Use Black for automatic formatting
- Use flake8 for linting
- Use mypy for type checking
- No unused imports or variables

Example:
```python
def process_indicator(indicator: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Process and validate a threat indicator.

    Args:
        indicator: Raw indicator data from source

    Returns:
        Processed indicator or None if invalid

    Raises:
        ValidationError: If indicator fails validation
    """
    pass
```

### TypeScript/JavaScript

- Follow ESLint configuration
- Use TypeScript for type safety
- Functional components with React Hooks
- Clear, descriptive variable names
- Use async/await over promises
- Handle errors gracefully

Example:
```typescript
interface IndicatorCardProps {
  indicator: Indicator;
  onClick?: () => void;
}

export const IndicatorCard: React.FC<IndicatorCardProps> = ({ indicator, onClick }) => {
  // Component implementation
};
```

### Testing

- **Unit Tests**: Test individual functions in isolation
- **Integration Tests**: Test API endpoints end-to-end
- **Mock External Services**: Use `unittest.mock` or `pytest-mock`
- **AAA Pattern**: Arrange, Act, Assert
- **Coverage Target**: >80% for all modules

Example:
```python
def test_normalize_indicator():
    # Arrange
    raw_indicator = {"indicator": "evil.com", "type": "domain"}

    # Act
    result = normalizer.normalize(raw_indicator)

    # Assert
    assert result["indicator_value"] == "evil.com"
    assert result["indicator_type"] == "domain"
```

### Git Commit Messages

Format: `<type>(<scope>): <subject>`

Examples:
```
feat(api): Add search endpoint with filters
fix(enrichment): Handle missing MITRE TTPs gracefully
docs(readme): Update installation instructions
test(normalizer): Add tests for edge cases
refactor(cache): Extract Redis client to separate module
```

## Project Structure

```
IDPI/
├── ingestion/          # Azure Functions for data ingestion
│   ├── connectors/     # External API connectors
│   ├── storage/        # Cosmos DB client
│   └── tests/          # Unit tests
├── api/                # FastAPI query API
│   ├── routers/        # API endpoints
│   ├── services/       # Business logic
│   └── tests/          # API tests
├── dashboard/          # React dashboard
│   ├── src/
│   │   ├── components/ # React components
│   │   ├── pages/      # Page components
│   │   └── services/   # API client
│   └── tests/          # Component tests
└── docs/               # Documentation
```

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md if applicable
5. Request review from maintainers
6. Address review feedback
7. Squash commits if requested

## Code Review Guidelines

Reviewers will check for:

- **Correctness**: Does the code work as intended?
- **Tests**: Are there adequate tests?
- **Style**: Does it follow coding standards?
- **Performance**: Are there obvious performance issues?
- **Security**: Are there security vulnerabilities?
- **Documentation**: Is the code well-documented?

## Questions?

- Open an issue for discussion
- Check existing issues and PRs first
- Be respectful and follow the [Code of Conduct](.github/CODE_OF_CONDUCT.md)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
