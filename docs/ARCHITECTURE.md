# ThreatStream Architecture

Architecture decisions, design patterns, and trade-offs for the ThreatStream Intelligence Pipeline.

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Decisions](#architecture-decisions)
3. [Design Patterns](#design-patterns)
4. [Data Flow](#data-flow)
5. [Performance Considerations](#performance-considerations)
6. [Security Architecture](#security-architecture)
7. [Trade-offs & Alternatives](#trade-offs--alternatives)

---

## System Overview

ThreatStream is a serverless, event-driven threat intelligence pipeline built on Azure. The architecture emphasizes:

- **Decoupling**: Independent stages communicating via events
- **Scalability**: Automatic scaling without capacity planning
- **Resilience**: Circuit breakers, retries, graceful degradation
- **Observability**: Comprehensive logging and monitoring
- **Cost Efficiency**: Pay-per-use serverless model

### High-Level Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                     External Threat Intel APIs                     │
│          (AlienVault OTX, AbuseIPDB, URLhaus)                     │
└─────────────────────────┬─────────────────────────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────────────────────────┐
│                     INGESTION LAYER                                │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐        │
│  │ HTTP Trigger │    │Timer Trigger │    │  Connectors  │        │
│  │  (On-Demand) │    │  (Scheduled) │    │   (OTX, etc) │        │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘        │
│         └─────────────┬──────┴────────────────────┘               │
│                       ▼                                            │
│              ┌─────────────────┐                                  │
│              │ Schema Validate │                                  │
│              │   + Transform   │                                  │
│              └────────┬────────┘                                  │
└───────────────────────┼────────────────────────────────────────────┘
                        ▼
┌───────────────────────────────────────────────────────────────────┐
│                     STORAGE LAYER                                  │
│              ┌──────────────────────┐                             │
│              │   Cosmos DB (Raw)    │                             │
│              │  - raw_indicators    │                             │
│              │  - TTL: 30 days      │                             │
│              └──────────┬───────────┘                             │
└───────────────────────────────────────────────────────────────────┘
                        │ (Change Feed)
                        ▼
┌───────────────────────────────────────────────────────────────────┐
│                  NORMALIZATION LAYER                               │
│  ┌─────────────────────────────────────────────────┐              │
│  │         Cosmos DB Change Feed Trigger           │              │
│  └──────────────────┬──────────────────────────────┘              │
│                     ▼                                              │
│  ┌──────────────┐  ┌───────────────┐  ┌─────────────────┐        │
│  │  Normalize   │→│ Deduplicate   │→│Detect Relations │        │
│  │  (Standardize│  │(Merge Sources)│  │  (IP→Domain)    │        │
│  └──────────────┘  └───────────────┘  └─────────────────┘        │
│                                 │                                  │
│                                 ▼                                  │
│                ┌────────────────────────────┐                     │
│                │  Cosmos DB (Normalized)    │                     │
│                │  - normalized_indicators   │                     │
│                │  - indicator_relationships │                     │
│                └────────────────────────────┘                     │
└───────────────────────────────────────────────────────────────────┘
                        │ (Change Feed)
                        ▼
┌───────────────────────────────────────────────────────────────────┐
│                   ENRICHMENT LAYER                                 │
│  ┌─────────────────────────────────────────────────┐              │
│  │         Cosmos DB Change Feed Trigger           │              │
│  └──────────────────┬──────────────────────────────┘              │
│                     ▼                                              │
│        ┌─────────────────────────────┐                            │
│        │    Filter (confidence ≥75)  │                            │
│        └───────────┬─────────────────┘                            │
│                    ▼                                               │
│        ┌─────────────────────────────┐                            │
│        │  Azure OpenAI (GPT-4o)      │                            │
│        │  - Structured Output        │                            │
│        │  - MITRE ATT&CK Mapping     │                            │
│        │  - Threat Classification    │                            │
│        └───────────┬─────────────────┘                            │
│                    ▼                                               │
│        ┌─────────────────────────────┐                            │
│        │  Cosmos DB (Enriched)       │                            │
│        │  - enriched_indicators      │                            │
│        └─────────────────────────────┘                            │
└───────────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────────────┐
│                       QUERY LAYER                                  │
│  ┌──────────────────────────────────────────────────┐             │
│  │              FastAPI Application                  │             │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐ │             │
│  │  │Indicators  │  │Relationships│  │  Stats     │ │             │
│  │  │  Router    │  │   Router    │  │  Router    │ │             │
│  │  └────────────┘  └────────────┘  └────────────┘ │             │
│  └──────────────────────┬───────────────────────────┘             │
│                         ▼                                          │
│           ┌─────────────────────────────┐                         │
│           │      Query Service          │                         │
│           │  - Parameterized Queries    │                         │
│           │  - Cursor Pagination        │                         │
│           └────────┬────────────────────┘                         │
│                    │                                               │
│          ┌─────────┴───────────┐                                  │
│          ▼                     ▼                                  │
│  ┌──────────────┐      ┌──────────────┐                          │
│  │ Redis Cache  │      │  Cosmos DB   │                          │
│  │ (Circuit     │      │  (Enriched)  │                          │
│  │  Breaker)    │      │              │                          │
│  └──────────────┘      └──────────────┘                          │
└───────────────────────────────────────────────────────────────────┘
```

---

## Architecture Decisions

### 1. Why Serverless (Azure Functions)?

**Decision**: Use Azure Functions for data pipeline stages instead of containers or VMs.

**Rationale**:
- **Event-Driven**: Natural fit for ETL pipeline triggered by timers and change feeds
- **Auto-Scaling**: Handles variable load without capacity planning
- **Cost-Effective**: Pay only for execution time (seconds), not idle time
- **Integrated Triggers**: Built-in Cosmos DB change feed and timer triggers
- **Simplified Operations**: No infrastructure management, automatic patching

**Trade-offs**:
- ❌ Cold start latency (mitigated with Always-On for production)
- ❌ Execution time limits (10 minutes max, acceptable for our use case)
- ✅ 90% cost reduction vs. always-on VMs for bursty workloads

**Alternatives Considered**:
- **Containers (AKS)**: Higher cost, unnecessary operational overhead for simple pipeline
- **VMs**: Highest cost, most operational burden

---

### 2. Why Cosmos DB?

**Decision**: Use Cosmos DB as primary data store instead of PostgreSQL or SQL Server.

**Rationale**:
- **Change Feed**: Real-time event stream enables event-driven architecture
- **Serverless Mode**: Pay per request, not provisioned capacity
- **Flexible Schema**: Handles varying indicator formats from different sources
- **Global Distribution**: Low-latency reads worldwide (if needed)
- **Automatic Indexing**: All fields indexed by default

**Trade-offs**:
- ❌ Higher cost than SQL for high-volume reads (mitigated with Redis caching)
- ❌ NoSQL query limitations (acceptable for our access patterns)
- ✅ Change feed eliminates need for polling or message queues
- ✅ Flexible schema simplifies adding new threat intel sources

**Alternatives Considered**:
- **PostgreSQL**: Lower cost, but no change feed, requires custom polling
- **SQL Server**: No serverless option, higher operational overhead
- **MongoDB**: Similar capabilities but Azure Cosmos DB better integrated

**Cost Optimization**:
```python
# 1. TTL on raw indicators (30 days)
# 2. Serverless mode (pay per RU)
# 3. Efficient partition keys
# 4. Redis caching for reads
# Estimated: $20-40/month for MVP
```

---

### 3. Why FastAPI for Query API?

**Decision**: Use FastAPI instead of Flask or Django.

**Rationale**:
- **Performance**: Async/await support, fast JSON serialization
- **Type Safety**: Pydantic validation prevents runtime errors
- **Auto Documentation**: OpenAPI/Swagger generation out-of-box
- **Modern**: Native async, dependency injection, standards-based
- **Developer Experience**: Excellent IDE support, clear error messages

**Trade-offs**:
- ❌ Smaller ecosystem than Flask
- ✅ 3x faster than Flask in benchmarks
- ✅ Type safety catches bugs before runtime

**Alternatives Considered**:
- **Flask**: Simpler, but no async, manual validation, no auto-docs
- **Django REST Framework**: Heavier, unnecessary ORM overhead for NoSQL

---

### 4. Why Redis for Caching?

**Decision**: Use Redis instead of in-memory caching or no caching.

**Rationale**:
- **Performance**: Sub-millisecond latency reduces Cosmos DB costs
- **Rate Limiting**: Built-in support via slowapi
- **Shared State**: Multiple API instances share cache
- **TTL Support**: Automatic cache expiration
- **Circuit Breaker**: Graceful degradation when unavailable

**Cache Strategy**:
```python
# 1. Indicator queries: 5 min TTL
# 2. Statistics: 5 min TTL
# 3. Relationships: 5 min TTL
# 4. Individual indicators: 10 min TTL
# 5. Circuit breaker: Degrades gracefully if Redis down
```

**Trade-offs**:
- ❌ Additional infrastructure component
- ✅ 80%+ cache hit rate reduces Cosmos DB RUs by 50%+
- ✅ Enables rate limiting without custom state management

---

### 5. Why GPT-4o for Enrichment?

**Decision**: Use Azure OpenAI GPT-4o with structured outputs instead of ML models.

**Rationale**:
- **Structured Outputs**: Guaranteed JSON schema compliance (zero parsing errors)
- **MITRE ATT&CK Knowledge**: Pre-trained on threat intelligence
- **No Training Required**: Works out-of-box, no labeled dataset needed
- **Cost-Effective**: $0.02 per 100 enrichments with filtering (confidence ≥75)

**Cost Optimization Strategy**:
```python
# 1. Only enrich confidence ≥75 (top 25%)
# 2. Skip re-enrichment within 24 hours
# 3. Use gpt-4o (cheaper than gpt-4)
# 4. Structured outputs reduce retry costs
# Estimated: $10-20/month for 50K indicators
```

**Trade-offs**:
- ❌ External dependency (API availability)
- ❌ Variable latency (2-5 seconds per enrichment)
- ✅ No ML infrastructure or training pipeline
- ✅ Immediate value without data science team

**Alternatives Considered**:
- **Custom ML Models**: Requires labeled data, training infra, ongoing maintenance
- **Rule-Based System**: Brittle, requires constant manual updates
- **Other LLMs**: GPT-4o has best price/performance for structured outputs

---

## Design Patterns

### 1. Circuit Breaker Pattern (Redis Cache)

Prevents cascading failures when Redis is unavailable.

```python
class CacheService:
    circuit_state = CircuitState.CLOSED  # CLOSED, OPEN, HALF_OPEN
    failure_count = 0
    failure_threshold = 3

    async def get(self, key):
        if self.circuit_state == CircuitState.OPEN:
            if time_since_last_failure > recovery_timeout:
                self.circuit_state = CircuitState.HALF_OPEN
            else:
                return None  # Fail fast, don't attempt call

        try:
            value = redis.get(key)
            self._record_success()
            return value
        except Exception:
            self._record_failure()
            if self.failure_count >= self.failure_threshold:
                self.circuit_state = CircuitState.OPEN
            return None
```

**Benefits**:
- Prevents repeated failures to unavailable service
- Automatic recovery testing
- Graceful degradation (API works without cache)

---

### 2. Retry with Exponential Backoff (External APIs)

Handles transient failures in external threat intel APIs.

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def _make_request(self, endpoint):
    response = requests.get(endpoint, timeout=30)
    response.raise_for_status()
    return response.json()
```

**Backoff Schedule**:
1. Attempt 1: Immediate
2. Attempt 2: Wait 4 seconds
3. Attempt 3: Wait 8 seconds

**Benefits**:
- Handles rate limiting and transient network errors
- Prevents overwhelming failing services
- Configurable max attempts and wait times

---

### 3. Event-Driven Architecture (Cosmos Change Feed)

Decouples pipeline stages using Cosmos DB change feed.

```python
@app.cosmos_db_trigger(
    arg_name="documents",
    container_name="raw_indicators",
    database_name="threatstream",
    connection="COSMOS_CONNECTION",
    lease_container_name="leases",
    create_lease_container_if_not_exists=True
)
async def normalization_function(documents: func.DocumentList):
    # Triggered automatically when raw indicators inserted
    for doc in documents:
        normalized = normalize_indicator(doc)
        cosmos_client.upsert(normalized)
```

**Benefits**:
- No polling required (real-time processing)
- Automatic retry and checkpointing
- Scales automatically with load
- Loose coupling between stages

---

### 4. Partition Key Strategy (Cosmos DB)

Prevents hot partitions with hash-based partition keys.

```python
def _generate_partition_key(self, indicator_value: str, indicator_type: str) -> str:
    """Generate partition key to avoid hot partitions"""
    # Combine type with hash prefix to distribute load
    # Creates 256 partitions per type (00-ff)
    hash_prefix = hashlib.md5(indicator_value.encode()).hexdigest()[:2]
    return f"{indicator_type}_{hash_prefix}"

# Example partition keys:
# domain_a3, domain_f7, IPv4_2c, IPv4_d9
# Distributes across 256 partitions per type
```

**Benefits**:
- Even distribution of data and load
- Avoids hot partition (single partition overload)
- Supports high throughput queries

---

### 5. Parameterized Queries (SQL Injection Prevention)

All Cosmos DB queries use parameters, never string interpolation.

```python
# ✅ SAFE - Parameterized
query = "SELECT * FROM c WHERE c.type = @type"
parameters = [{"name": "@type", "value": user_input}]
results = cosmos_client.query_items(container, query, parameters)

# ❌ UNSAFE - String interpolation (NEVER DO THIS)
query = f"SELECT * FROM c WHERE c.type = '{user_input}'"
```

**Benefits**:
- Prevents SQL injection attacks
- Query plan caching (better performance)
- Automatic escaping of special characters

---

## Data Flow

### Ingestion Flow

```
1. Timer Trigger (daily) OR HTTP Trigger (on-demand)
   ↓
2. Connector fetches data from external API
   ↓
3. Schema validation with Pydantic
   ↓
4. Transform to standard format
   ↓
5. Write to Cosmos DB (raw_indicators)
   ↓
6. Change feed emits event
```

### Normalization Flow

```
1. Change feed trigger fires
   ↓
2. Extract indicator from document
   ↓
3. Normalize format (lowercase, strip spaces)
   ↓
4. Query for existing indicators (same value, different sources)
   ↓
5. Merge/deduplicate (weighted average confidence)
   ↓
6. Detect relationships (IP from domain, URL from hash)
   ↓
7. Write to normalized_indicators + indicator_relationships
   ↓
8. Change feed emits event
```

### Enrichment Flow

```
1. Change feed trigger fires
   ↓
2. Filter: Skip if confidence <75 (cost optimization)
   ↓
3. Check if enriched within 24 hours (deduplication)
   ↓
4. Call Azure OpenAI with structured output schema
   ↓
5. Validate MITRE ATT&CK techniques
   ↓
6. Write to enriched_indicators
```

### Query Flow (with caching)

```
1. API request with X-API-Key header
   ↓
2. Validate API key (Cosmos DB lookup)
   ↓
3. Check rate limit (Redis)
   ↓
4. Check cache (Redis with circuit breaker)
   ├─ Cache hit → Return cached result
   └─ Cache miss ↓
5. Query Cosmos DB (parameterized)
   ↓
6. Cache result (5-10 min TTL)
   ↓
7. Return response
```

---

## Performance Considerations

### Query Optimization

**Problem**: Cosmos DB charges per Request Unit (RU), queries can be expensive.

**Solutions**:
1. **Redis Caching**: 80%+ cache hit rate reduces Cosmos RUs by 50%+
2. **Pagination**: Cursor-based pagination limits result set size
3. **Selective Indexing**: Only index fields used in queries
4. **Parameterized Queries**: Enables query plan caching

**Metrics**:
- Cached query: <100ms, ~0 RUs
- Uncached query: 200-800ms, 2-5 RUs per query
- Cost: ~$0.008 per 1000 cached queries

---

### Enrichment Cost Optimization

**Problem**: GPT-4o costs $2.50 per 1M input tokens, can get expensive.

**Solutions**:
1. **Confidence Threshold**: Only enrich indicators with confidence ≥75 (top quartile)
2. **Deduplication**: Skip re-enrichment within 24 hours
3. **Structured Outputs**: Eliminate retry costs from parsing errors
4. **Batch Processing**: Process in batches to reduce API overhead

**Metrics**:
- Average enrichment: ~500 tokens = $0.00125 per indicator
- With 75% threshold: Enriching 25% of indicators saves 75% cost
- Estimated monthly cost: $10-20 for 50K new indicators

---

## Security Architecture

### Defense in Depth

1. **API Layer**:
   - API key authentication (X-API-Key header)
   - Rate limiting per API key (tier-based)
   - Input validation (Pydantic models)
   - HTTPS only (TLS 1.2+)

2. **Application Layer**:
   - Parameterized queries (SQL injection prevention)
   - Output encoding (XSS prevention)
   - Dependency scanning (Dependabot)
   - Secrets in environment variables (never in code)

3. **Data Layer**:
   - Azure Key Vault for secrets
   - Cosmos DB encryption at rest
   - Network isolation (VNet integration in production)
   - Audit logging (Azure Monitor)

4. **Infrastructure Layer**:
   - Managed identities (no credentials in code)
   - RBAC for Azure resources
   - Resource locks (prevent accidental deletion)
   - Cost alerts (prevent runaway bills)

---

## Trade-offs & Alternatives

### Cosmos DB vs. PostgreSQL

| Aspect | Cosmos DB ✅ | PostgreSQL |
|--------|-------------|-----------|
| **Change Feed** | ✅ Built-in | ❌ Requires polling |
| **Schema** | ✅ Flexible | ⚠️ Rigid |
| **Cost (low volume)** | ✅ Serverless cheap | ✅ Cheap |
| **Cost (high volume)** | ❌ Expensive | ✅ Much cheaper |
| **Global Distribution** | ✅ Easy | ⚠️ Complex |
| **Query Language** | ⚠️ SQL-like | ✅ Full SQL |
| **Operational Overhead** | ✅ Fully managed | ⚠️ Requires tuning |

**Verdict**: Cosmos DB chosen for change feed and serverless mode. Would revisit if query volume exceeds 1M/month.

---

### Serverless vs. Containers

| Aspect | Azure Functions ✅ | Containers (AKS) |
|--------|---------------------|------------------|
| **Cost (bursty load)** | ✅ Very low | ❌ High (always-on) |
| **Cold Start** | ❌ 1-3 seconds | ✅ None |
| **Scaling** | ✅ Automatic | ⚠️ Manual config |
| **Complexity** | ✅ Low | ❌ High |
| **Trigger Support** | ✅ Native | ⚠️ Custom polling |
| **Portability** | ⚠️ Azure-specific | ✅ Any cloud |

**Verdict**: Azure Functions chosen for simplicity and cost. Would revisit if latency SLAs require sub-100ms response times.

---

## Future Architecture Considerations

### Scaling Beyond MVP

**At 1M indicators:**
- Consider PostgreSQL to reduce query costs
- Implement read replicas for query API
- Add CDN for static content

**At 10M indicators:**
- Partition data by region or time window
- Implement data archival strategy
- Consider event streaming (Event Hubs)

**At 100M indicators:**
- Migrate to data lake (Azure Data Lake)
- Implement distributed caching (Redis cluster)
- Consider Apache Spark for batch processing

---

## Summary

The architecture prioritizes:

1. **Simplicity**: Serverless eliminates operational overhead
2. **Cost Efficiency**: Pay-per-use model optimizes for bursty workload
3. **Resilience**: Circuit breakers, retries, graceful degradation
4. **Maintainability**: Clear separation of concerns, event-driven
5. **Security**: Defense in depth, least privilege, no secrets in code

Trade-offs are acceptable for target scale (MVP: 50K-500K indicators, 1K queries/day).

---

## References

- [Azure Functions Best Practices](https://learn.microsoft.com/en-us/azure/azure-functions/functions-best-practices)
- [Cosmos DB Partition Key Design](https://learn.microsoft.com/en-us/azure/cosmos-db/partitioning-overview)
- [FastAPI Performance](https://fastapi.tiangolo.com/benchmarks/)
- [Azure OpenAI Structured Outputs](https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/structured-outputs)
