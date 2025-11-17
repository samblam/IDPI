# ThreatStream Setup Guide

Complete installation and configuration guide for local development and Azure deployment.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development Setup](#local-development-setup)
3. [Azure Resources Setup](#azure-resources-setup)
4. [Configuration](#configuration)
5. [Running the Application](#running-the-application)
6. [Testing](#testing)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| **Python** | 3.11+ | Runtime environment |
| **pip** | Latest | Package management |
| **Git** | Latest | Version control |
| **Redis** | 5.0+ | Caching and rate limiting |
| **Docker** (optional) | Latest | Local Cosmos DB emulator |

### Required Accounts & API Keys

1. **Azure Subscription** (or Cosmos DB Emulator for local dev)
2. **Azure OpenAI Access** (requires application/approval)
3. **AlienVault OTX API Key** (free registration)
4. **AbuseIPDB API Key** (free tier or paid)

---

## Local Development Setup

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/IDPI.git
cd IDPI/ingestion
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install all dependencies
pip install -r requirements.txt

# Verify installation
pip list
```

### 4. Install Redis

#### macOS (Homebrew)
```bash
brew install redis
brew services start redis
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install redis-server
sudo systemctl start redis
```

#### Windows
```bash
# Download and run Redis Windows port
# https://github.com/microsoftarchive/redis/releases
```

#### Docker (All platforms)
```bash
docker run -d -p 6379:6379 redis:latest
```

### 5. Install Cosmos DB Emulator (Optional - for local development)

#### Windows
```bash
# Download and install:
# https://aka.ms/cosmosdb-emulator
```

#### Linux/Mac (Docker)
```bash
docker pull mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator

docker run -d \
  -p 8081:8081 -p 10251:10251 -p 10252:10252 -p 10253:10253 -p 10254:10254 \
  -e AZURE_COSMOS_EMULATOR_PARTITION_COUNT=10 \
  -e AZURE_COSMOS_EMULATOR_ENABLE_DATA_PERSISTENCE=true \
  --name=cosmos-emulator \
  mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator
```

**Emulator Connection String**:
```
AccountEndpoint=https://localhost:8081/;AccountKey=C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==
```

---

## Azure Resources Setup

### 1. Install Azure CLI

```bash
# macOS
brew install azure-cli

# Ubuntu/Debian
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Windows
# Download from https://aka.ms/installazurecliwindows
```

### 2. Login to Azure

```bash
az login
az account set --subscription "your-subscription-id"
```

### 3. Create Resource Group

```bash
az group create \
  --name threatstream-rg \
  --location eastus
```

### 4. Create Cosmos DB Account

```bash
# Create account (serverless)
az cosmosdb create \
  --name threatstream-cosmos \
  --resource-group threatstream-rg \
  --kind GlobalDocumentDB \
  --default-consistency-level Session \
  --enable-automatic-failover true \
  --capabilities EnableServerless

# Create database
az cosmosdb sql database create \
  --account-name threatstream-cosmos \
  --resource-group threatstream-rg \
  --name threatstream

# Create containers
az cosmosdb sql container create \
  --account-name threatstream-cosmos \
  --database-name threatstream \
  --resource-group threatstream-rg \
  --name raw_indicators \
  --partition-key-path "/partition_key"

az cosmosdb sql container create \
  --account-name threatstream-cosmos \
  --database-name threatstream \
  --resource-group threatstream-rg \
  --name normalized_indicators \
  --partition-key-path "/partition_key"

az cosmosdb sql container create \
  --account-name threatstream-cosmos \
  --database-name threatstream \
  --resource-group threatstream-rg \
  --name enriched_indicators \
  --partition-key-path "/partition_key"

az cosmosdb sql container create \
  --account-name threatstream-cosmos \
  --database-name threatstream \
  --resource-group threatstream-rg \
  --name indicator_relationships \
  --partition-key-path "/partition_key"

az cosmosdb sql container create \
  --account-name threatstream-cosmos \
  --database-name threatstream \
  --resource-group threatstream-rg \
  --name api_keys \
  --partition-key-path "/api_key"
```

### 5. Create Azure OpenAI Resource

```bash
# Apply for access first: https://aka.ms/oai/access

# Create resource
az cognitiveservices account create \
  --name threatstream-openai \
  --resource-group threatstream-rg \
  --kind OpenAI \
  --sku S0 \
  --location eastus

# Deploy GPT-4o model
az cognitiveservices account deployment create \
  --name threatstream-openai \
  --resource-group threatstream-rg \
  --deployment-name gpt-4o \
  --model-name gpt-4o \
  --model-version "2024-08-06" \
  --model-format OpenAI \
  --sku-capacity 10 \
  --sku-name "Standard"
```

### 6. Create Redis Cache

```bash
az redis create \
  --name threatstream-cache \
  --resource-group threatstream-rg \
  --location eastus \
  --sku Basic \
  --vm-size c0 \
  --enable-non-ssl-port
```

### 7. Create Function App

```bash
# Create storage account
az storage account create \
  --name threatstreamfunc \
  --resource-group threatstream-rg \
  --location eastus \
  --sku Standard_LRS

# Create function app
az functionapp create \
  --name threatstream-functions \
  --resource-group threatstream-rg \
  --consumption-plan-location eastus \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --storage-account threatstreamfunc
```

---

## Configuration

### 1. Get API Keys from Threat Intel Sources

#### AlienVault OTX
1. Register at https://otx.alienvault.com/
2. Go to Settings → API Key
3. Copy your API key

#### AbuseIPDB
1. Register at https://www.abuseipdb.com/
2. Go to Account → API
3. Copy your API key

### 2. Get Azure Connection Strings

```bash
# Cosmos DB connection string
az cosmosdb keys list \
  --name threatstream-cosmos \
  --resource-group threatstream-rg \
  --type connection-strings

# OpenAI endpoint and key
az cognitiveservices account show \
  --name threatstream-openai \
  --resource-group threatstream-rg \
  --query properties.endpoint -o tsv

az cognitiveservices account keys list \
  --name threatstream-openai \
  --resource-group threatstream-rg

# Redis connection string
az redis list-keys \
  --name threatstream-cache \
  --resource-group threatstream-rg
```

### 3. Create Environment File

Create `.env` file in `ingestion/` directory:

```bash
# Cosmos DB
COSMOS_ENDPOINT=https://threatstream-cosmos.documents.azure.com:443/
COSMOS_KEY=your-cosmos-primary-key
COSMOS_DATABASE=threatstream

# Azure OpenAI
OPENAI_ENDPOINT=https://threatstream-openai.openai.azure.com/
OPENAI_API_KEY=your-openai-key
OPENAI_MODEL=gpt-4o-2024-08-06

# Threat Intel Sources
OTX_API_KEY=your-otx-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-key

# Redis
REDIS_HOST=threatstream-cache.redis.cache.windows.net
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# API Configuration
API_KEY=generate-secure-api-key-here

# Optional: For local development with emulator
# COSMOS_ENDPOINT=https://localhost:8081/
# COSMOS_KEY=C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==
# REDIS_HOST=localhost
```

### 4. Load Environment Variables

```bash
# Load from .env file
set -a
source .env
set +a

# Or export manually
export COSMOS_ENDPOINT=https://...
export COSMOS_KEY=...
# etc.
```

---

## Running the Application

### 1. Start Redis

```bash
# If using system Redis
redis-server

# If using Docker
docker start redis  # or redis container name
```

### 2. Run Azure Functions (Ingestion Pipeline)

```bash
cd ingestion

# Install Azure Functions Core Tools if not installed
# https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local

# Start functions locally
func start
```

**Output**:
```
Azure Functions Core Tools
Core Tools Version: 4.0.5455

Functions:
  http_ingestion: [POST] http://localhost:7071/api/ingest
  timer_ingestion: timer trigger
  normalization_function: cosmosDBTrigger
  enrichment_function: cosmosDBTrigger
```

### 3. Run Query API (FastAPI)

```bash
cd ingestion

# Start FastAPI development server
uvicorn api.main:app --reload --port 8000
```

**Output**:
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000
```

### 4. Access Interactive Documentation

Open browser to:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 5. Test Health Check

```bash
curl http://localhost:8000/health
```

**Expected Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

---

## Testing

### 1. Run All Tests

```bash
cd ingestion

# Run all tests
pytest -v

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific module
pytest tests/test_enrichment_engine.py -v
```

### 2. Run Integration Tests

```bash
# Integration tests only
pytest -m integration

# Unit tests only
pytest -m unit
```

### 3. View Coverage Report

```bash
# Generate HTML coverage report
pytest --cov=. --cov-report=html

# Open in browser (macOS)
open htmlcov/index.html

# Open in browser (Linux)
xdg-open htmlcov/index.html

# Open in browser (Windows)
start htmlcov/index.html
```

---

## Troubleshooting

### Common Issues

#### 1. Cosmos DB Connection Errors

**Error**: `Unable to reach https://localhost:8081/`

**Solution**:
```bash
# If using emulator, verify it's running
docker ps | grep cosmos

# Restart emulator if needed
docker restart cosmos-emulator

# Check firewall/antivirus blocking port 8081
```

#### 2. Redis Connection Refused

**Error**: `Error 111 connecting to localhost:6379. Connection refused.`

**Solution**:
```bash
# Verify Redis is running
redis-cli ping  # Should respond "PONG"

# Start Redis if not running
redis-server

# Or with Docker
docker start redis
```

#### 3. OpenAI Authentication Error

**Error**: `AuthenticationError: Incorrect API key provided`

**Solution**:
```bash
# Verify endpoint and key
echo $OPENAI_ENDPOINT
echo $OPENAI_API_KEY

# Test with Azure CLI
az cognitiveservices account keys list \
  --name threatstream-openai \
  --resource-group threatstream-rg
```

#### 4. Module Import Errors

**Error**: `ModuleNotFoundError: No module named 'fastapi'`

**Solution**:
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Verify virtual environment is activated
which python  # Should show venv/bin/python
```

#### 5. Azure Functions Not Starting

**Error**: `Worker was unable to load function`

**Solution**:
```bash
# Install Azure Functions Core Tools
# https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local

# Verify Python version
python --version  # Should be 3.11+

# Reinstall dependencies
pip install -r requirements.txt
```

### Debug Mode

Enable debug logging:

```bash
# Set environment variable
export FUNCTIONS_WORKER_RUNTIME=python
export AZURE_FUNCTIONS_ENVIRONMENT=development
export DEBUG=1

# Run with verbose output
func start --verbose
```

### Clean Installation

If all else fails, start fresh:

```bash
# Remove virtual environment
rm -rf venv

# Create new virtual environment
python -m venv venv
source venv/bin/activate

# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Clear pytest cache
rm -rf .pytest_cache
rm -rf htmlcov

# Restart Redis
redis-cli FLUSHALL

# Restart Cosmos emulator (if using)
docker restart cosmos-emulator
```

---

## Next Steps

After successful setup:

1. **Review [API Documentation](./API.md)** - Learn about available endpoints
2. **Review [Architecture](./ARCHITECTURE.md)** - Understand design decisions
3. **Review [Testing Guide](./TESTING.md)** - Learn testing strategy
4. **Start Ingestion** - Trigger HTTP ingestion or wait for timer trigger
5. **Query Data** - Use FastAPI endpoints to query enriched indicators

---

## Support

For setup issues:
- **Documentation**: [README](../README.md)
- **GitHub Issues**: [Report a problem](https://github.com/yourusername/IDPI/issues)
- **Email**: samuel.barefoot@example.com
