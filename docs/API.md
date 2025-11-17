# ThreatStream API Reference

Complete API documentation for the ThreatStream Intelligence Pipeline Query API.

## Base URL

- **Local Development**: `http://localhost:8000`
- **Production**: `https://your-api.azurewebsites.net`

## Authentication

All API endpoints (except `/health`) require authentication via API key.

### Header Format

```http
X-API-Key: your-api-key-here
```

### API Key Tiers

| Tier | Rate Limit | Features |
|------|------------|----------|
| **Free** | 10 requests/minute | Basic access |
| **Standard** | 60 requests/minute | Standard access |
| **Premium** | 300 requests/minute | Priority access |
| **Enterprise** | 1000 requests/minute | Full access + SLA |

### Rate Limiting

Rate limits are enforced per API key. Exceeding limits results in:

**Response**:
```json
HTTP/1.1 429 Too Many Requests
{
  "error": "Rate limit exceeded",
  "retry_after": 30
}
```

---

## Endpoints

### Health Check

Check API health status (no authentication required).

**Endpoint**: `GET /health`

**Request**:
```bash
curl http://localhost:8000/health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

---

### Query Indicators

Retrieve threat indicators with optional filtering and pagination.

**Endpoint**: `GET /indicators`

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `indicator_type` | string | No | Filter by type: `domain`, `IPv4`, `IPv6`, `url`, `hash` |
| `confidence_min` | integer | No | Minimum confidence score (0-100) |
| `page_size` | integer | No | Items per page (default: 100, max: 1000) |
| `continuation_token` | string | No | Token for next page |

**Request**:
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/indicators?indicator_type=domain&confidence_min=80&page_size=10"
```

**Response**:
```json
{
  "items": [
    {
      "id": "otx_malicious.com",
      "indicator_value": "malicious.com",
      "indicator_type": "domain",
      "confidence_score": 92,
      "source_count": 3,
      "sources": [
        {
          "name": "otx",
          "first_seen": "2024-01-10T12:00:00Z",
          "tags": ["malware", "phishing"]
        },
        {
          "name": "abuseipdb",
          "first_seen": "2024-01-11T08:30:00Z",
          "confidence": 95
        },
        {
          "name": "urlhaus",
          "first_seen": "2024-01-12T14:15:00Z",
          "malware_family": "Emotet"
        }
      ],
      "enrichment": {
        "classification": "Phishing Infrastructure",
        "threat_actor": "TA505",
        "mitre_ttps": ["T1566.002", "T1071.001"],
        "severity": "High",
        "recommended_actions": [
          "Block domain at DNS level",
          "Alert SOC team",
          "Check for compromised credentials"
        ]
      },
      "enriched_at": "2024-01-12T15:00:00Z",
      "created_at": "2024-01-10T12:00:00Z",
      "updated_at": "2024-01-12T15:00:00Z"
    }
  ],
  "continuation_token": "eyJsYXN0X2lkIjogIm90eF9tYWxpY2lvdXMuY29tIn0=",
  "count": 1
}
```

**Status Codes**:
- `200 OK` - Success
- `401 Unauthorized` - Missing or invalid API key
- `429 Too Many Requests` - Rate limit exceeded

---

### Get Indicator by ID

Retrieve a specific indicator by its unique ID.

**Endpoint**: `GET /indicators/{indicator_id}`

**Path Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `indicator_id` | string | Yes | Unique indicator ID |

**Request**:
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/indicators/otx_malicious.com"
```

**Response**:
```json
{
  "id": "otx_malicious.com",
  "indicator_value": "malicious.com",
  "indicator_type": "domain",
  "confidence_score": 92,
  "source_count": 3,
  "sources": [...],
  "enrichment": {...},
  "enriched_at": "2024-01-12T15:00:00Z",
  "created_at": "2024-01-10T12:00:00Z",
  "updated_at": "2024-01-12T15:00:00Z"
}
```

**Status Codes**:
- `200 OK` - Success
- `404 Not Found` - Indicator not found
- `401 Unauthorized` - Missing or invalid API key

---

### Search Indicators

Full-text search across indicator values.

**Endpoint**: `GET /indicators/search`

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | Yes | Search query (minimum 1 character) |
| `page_size` | integer | No | Items per page (default: 100, max: 1000) |

**Request**:
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/indicators/search?q=malicious&page_size=5"
```

**Response**:
```json
{
  "items": [
    {
      "id": "otx_malicious.com",
      "indicator_value": "malicious.com",
      "indicator_type": "domain",
      "confidence_score": 92,
      ...
    },
    {
      "id": "otx_very-malicious.net",
      "indicator_value": "very-malicious.net",
      "indicator_type": "domain",
      "confidence_score": 88,
      ...
    }
  ],
  "continuation_token": null,
  "count": 2
}
```

**Security Note**: Search uses parameterized queries to prevent SQL injection.

---

### Query Relationships

Retrieve relationships between indicators (e.g., domain resolves to IP).

**Endpoint**: `GET /relationships`

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `indicator_id` | string | No | Filter by source or target indicator |
| `relationship_type` | string | No | Filter by type: `resolves_to`, `downloads`, `communicates_with`, `contains` |

**Request**:
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/relationships?indicator_id=malicious.com"
```

**Response**:
```json
{
  "items": [
    {
      "id": "rel_malicious.com_192.168.1.1",
      "source_id": "malicious.com",
      "target_id": "192.168.1.1",
      "relationship_type": "resolves_to",
      "confidence": 0.98,
      "detected_at": "2024-01-10T12:00:00Z"
    },
    {
      "id": "rel_malicious.com_payload.exe",
      "source_id": "malicious.com",
      "target_id": "payload.exe",
      "relationship_type": "downloads",
      "confidence": 0.95,
      "detected_at": "2024-01-11T08:30:00Z"
    }
  ],
  "count": 2
}
```

---

### Platform Statistics

Retrieve platform-wide statistics about indicators.

**Endpoint**: `GET /stats`

**Request**:
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8000/stats"
```

**Response**:
```json
{
  "total_indicators": 45672,
  "by_type": {
    "domain": 18234,
    "IPv4": 12456,
    "url": 8932,
    "hash": 6050
  },
  "last_updated": null
}
```

**Caching**: Statistics are cached for 5 minutes for performance.

---

### Real-Time Indicator Stream (SSE)

Server-Sent Events stream for real-time indicator updates.

**Endpoint**: `GET /stream/indicators`

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `indicator_type` | string | No | Filter by indicator type |
| `confidence_min` | integer | No | Minimum confidence score (default: 75) |
| `heartbeat_interval` | integer | No | Heartbeat interval in seconds (10-300, default: 30) |

**Request**:
```bash
curl -H "X-API-Key: your-api-key" \
  -H "Accept: text/event-stream" \
  "http://localhost:8000/stream/indicators?confidence_min=90"
```

**Response** (Server-Sent Events):
```
event: heartbeat
data: {"timestamp":"2024-01-15T10:30:00Z","status":"alive"}

event: indicator
data: {"id":"new_threat.com","indicator_value":"new_threat.com","indicator_type":"domain","confidence_score":95,...}

event: heartbeat
data: {"timestamp":"2024-01-15T10:30:30Z","status":"alive"}

event: indicator
data: {"id":"192.0.2.1","indicator_value":"192.0.2.1","indicator_type":"IPv4","confidence_score":92,...}

event: error
data: {"error":"Connection timeout","timestamp":"2024-01-15T10:31:00Z"}

event: close
data: {"reason":"client_disconnect"}
```

**Event Types**:
- `heartbeat` - Keep-alive ping (every N seconds)
- `indicator` - New or updated indicator
- `error` - Error occurred
- `close` - Stream closing

**Client Example** (JavaScript):
```javascript
const eventSource = new EventSource(
  'http://localhost:8000/stream/indicators?confidence_min=90',
  {
    headers: {
      'X-API-Key': 'your-api-key'
    }
  }
);

eventSource.addEventListener('indicator', (event) => {
  const indicator = JSON.parse(event.data);
  console.log('New indicator:', indicator);
});

eventSource.addEventListener('heartbeat', (event) => {
  const heartbeat = JSON.parse(event.data);
  console.log('Heartbeat:', heartbeat.timestamp);
});

eventSource.onerror = (error) => {
  console.error('Stream error:', error);
  eventSource.close();
};
```

---

## Error Responses

### Standard Error Format

```json
{
  "error": "Error message",
  "detail": "Detailed error description",
  "code": "ERROR_CODE"
}
```

### Common Error Codes

| HTTP Status | Error | Description |
|-------------|-------|-------------|
| `400 Bad Request` | Invalid input | Invalid query parameters or request body |
| `401 Unauthorized` | API key required | Missing X-API-Key header |
| `403 Forbidden` | Invalid API key | API key is invalid or disabled |
| `404 Not Found` | Resource not found | Requested resource doesn't exist |
| `429 Too Many Requests` | Rate limit exceeded | Too many requests for your tier |
| `500 Internal Server Error` | Internal error | Unexpected server error |

---

## Response Headers

### Standard Headers

```http
Content-Type: application/json
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1705315800
```

### Cache Headers

Cached responses include:

```http
Cache-Control: public, max-age=300
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
```

---

## Pagination

### Cursor-Based Pagination

For endpoints that return large datasets, use cursor-based pagination:

1. **First Request**:
```bash
GET /indicators?page_size=100
```

2. **Response includes continuation token**:
```json
{
  "items": [...],
  "continuation_token": "eyJsYXN0X2lkIjogInNvbWUtaWQifQ==",
  "count": 100
}
```

3. **Next Page Request**:
```bash
GET /indicators?page_size=100&continuation_token=eyJsYXN0X2lkIjogInNvbWUtaWQifQ==
```

4. **Last Page** (no continuation token):
```json
{
  "items": [...],
  "continuation_token": null,
  "count": 45
}
```

---

## Interactive Documentation

### Swagger UI

Visit `http://localhost:8000/docs` for interactive API documentation with:
- Try-it-out functionality
- Request/response examples
- Schema definitions
- Authentication testing

### ReDoc

Visit `http://localhost:8000/redoc` for alternative documentation view.

---

## SDKs & Examples

### Python

```python
import requests

API_BASE = "http://localhost:8000"
API_KEY = "your-api-key"

headers = {"X-API-Key": API_KEY}

# Query indicators
response = requests.get(
    f"{API_BASE}/indicators",
    headers=headers,
    params={"indicator_type": "domain", "confidence_min": 80}
)
indicators = response.json()

# Search
response = requests.get(
    f"{API_BASE}/indicators/search",
    headers=headers,
    params={"q": "malicious"}
)
results = response.json()

# Get relationships
response = requests.get(
    f"{API_BASE}/relationships",
    headers=headers,
    params={"indicator_id": "evil.com"}
)
relationships = response.json()
```

### cURL

```bash
# Set API key
API_KEY="your-api-key"

# Query indicators
curl -H "X-API-Key: $API_KEY" \
  "http://localhost:8000/indicators?indicator_type=domain&confidence_min=80"

# Search
curl -H "X-API-Key: $API_KEY" \
  "http://localhost:8000/indicators/search?q=malicious"

# Get stats
curl -H "X-API-Key: $API_KEY" \
  "http://localhost:8000/stats"
```

### JavaScript (Fetch)

```javascript
const API_BASE = 'http://localhost:8000';
const API_KEY = 'your-api-key';

const headers = {
  'X-API-Key': API_KEY,
  'Content-Type': 'application/json'
};

// Query indicators
const response = await fetch(
  `${API_BASE}/indicators?indicator_type=domain&confidence_min=80`,
  { headers }
);
const indicators = await response.json();

// Search
const searchResponse = await fetch(
  `${API_BASE}/indicators/search?q=malicious`,
  { headers }
);
const results = await searchResponse.json();
```

---

## Best Practices

### Performance

1. **Use caching**: Responses are cached when possible
2. **Filter aggressively**: Use `indicator_type` and `confidence_min` to reduce payload size
3. **Paginate large requests**: Use `page_size` to limit response size
4. **Monitor rate limits**: Check `X-RateLimit-*` headers

### Security

1. **Secure API keys**: Never commit API keys to version control
2. **Use HTTPS**: Always use HTTPS in production
3. **Rotate keys**: Regularly rotate API keys
4. **Validate inputs**: Always validate and sanitize user inputs

### Integration

1. **Handle errors gracefully**: Implement retry logic with exponential backoff
2. **Monitor for rate limits**: Track `X-RateLimit-Remaining` header
3. **Use SSE for real-time**: Prefer Server-Sent Events over polling
4. **Cache client-side**: Implement client-side caching when appropriate

---

## Support

For API issues or questions:
- **Documentation**: [README](../README.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/IDPI/issues)
- **Email**: samuel.barefoot@example.com
