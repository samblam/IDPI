# ThreatStream Infrastructure

This directory contains Terraform configuration for deploying the ThreatStream Intelligence Pipeline to Azure.

## Prerequisites

- [Terraform](https://www.terraform.io/downloads.html) >= 1.5.0
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) >= 2.50.0
- Active Azure subscription
- Azure OpenAI access (requires application approval)

## Quick Start

### 1. Login to Azure

```bash
az login
az account set --subscription "<your-subscription-id>"
```

### 2. Configure Variables

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
```

### 3. Initialize Terraform

```bash
terraform init
```

### 4. Review Plan

```bash
terraform plan
```

### 5. Deploy

```bash
terraform apply
```

## Resources Created

This Terraform configuration creates the following Azure resources:

- **Resource Group**: Container for all resources
- **Cosmos DB Account**: Serverless NoSQL database for threat indicators
- **Azure Functions**: Serverless compute for data ingestion and processing
- **Azure OpenAI**: GPT-4o for threat enrichment
- **Redis Cache**: Caching layer for API performance
- **Container Registry**: Docker images for API
- **Container Apps**: Hosting for FastAPI query API
- **Application Insights**: Monitoring and logging
- **Key Vault**: Secure storage for secrets and API keys
- **Storage Account**: Azure Functions runtime storage

## Cost Estimate

**Monthly costs (approximate):**
- Cosmos DB (serverless): $30-50
- Azure Functions (consumption): $5-10
- Azure OpenAI (GPT-4o): $50-100 (depends on usage)
- Redis Cache (Basic C0): $16
- Container Apps: $15-30
- Container Registry (Basic): $5
- Storage Account: $1-2
- Application Insights: $0-5

**Total: ~$120-220/month**

## Configuration

### Required Variables

See `terraform.tfvars.example` for all required variables:

- `location`: Azure region (e.g., "eastus")
- `environment`: Deployment environment ("dev", "staging", "prod")
- `project_name`: Project identifier (default: "threatstream")

### Optional Variables

- `cosmos_max_throughput`: Max RU/s for Cosmos DB (default: 1000)
- `redis_capacity`: Redis cache size (default: 0 = 250MB)
- `function_always_on`: Keep functions warm (default: false)

## Outputs

After deployment, Terraform outputs:

- Cosmos DB endpoint and connection string
- Azure Functions URL
- Container Apps API URL
- Application Insights instrumentation key
- Key Vault URI

Access outputs:
```bash
terraform output
terraform output -json > outputs.json
```

## State Management

### Local State (Default)

State is stored locally in `terraform.tfstate`. **Keep this file secure** as it contains sensitive information.

### Remote State (Recommended for Teams)

Use Azure Storage for remote state:

1. Create storage account:
```bash
az storage account create \
  --name tfstate<random> \
  --resource-group rg-terraform-state \
  --location eastus \
  --sku Standard_LRS

az storage container create \
  --name tfstate \
  --account-name tfstate<random>
```

2. Uncomment backend configuration in `backend.tf`

3. Initialize with backend:
```bash
terraform init -backend-config="storage_account_name=tfstate<random>"
```

## Deployment Workflow

### Development Environment

```bash
terraform workspace new dev
terraform apply -var="environment=dev"
```

### Production Environment

```bash
terraform workspace new prod
terraform apply -var="environment=prod"
```

## Secrets Management

Sensitive values (API keys, connection strings) are stored in **Azure Key Vault**.

Add secrets after deployment:

```bash
# Get Key Vault name from outputs
KEY_VAULT_NAME=$(terraform output -raw key_vault_name)

# Add secrets
az keyvault secret set --vault-name $KEY_VAULT_NAME --name "OTX-API-KEY" --value "your-otx-key"
az keyvault secret set --vault-name $KEY_VAULT_NAME --name "ABUSEIPDB-API-KEY" --value "your-abuseipdb-key"
az keyvault secret set --vault-name $KEY_VAULT_NAME --name "OPENAI-API-KEY" --value "your-openai-key"
```

## Updating Infrastructure

```bash
# Review changes
terraform plan

# Apply changes
terraform apply

# Destroy specific resource
terraform destroy -target=azurerm_redis_cache.main
```

## Troubleshooting

### Common Issues

**1. Azure OpenAI not available**
```
Error: Azure OpenAI is not available in this subscription
```
Solution: Apply for Azure OpenAI access at https://aka.ms/oai/access

**2. Quota exceeded**
```
Error: Quota exceeded for resource type 'cores'
```
Solution: Request quota increase or choose smaller SKUs

**3. Name already exists**
```
Error: Storage account name already taken
```
Solution: Change `project_name` variable to ensure unique names

### Enable Debug Logging

```bash
export TF_LOG=DEBUG
terraform apply
```

## Clean Up

**WARNING**: This will delete all resources and data.

```bash
terraform destroy
```

## Directory Structure

```
infrastructure/
├── README.md                 # This file
├── main.tf                   # Main resource definitions
├── variables.tf              # Input variables
├── outputs.tf                # Output values
├── providers.tf              # Provider configuration
├── backend.tf                # State backend configuration
├── terraform.tfvars.example  # Example variable values
├── modules/                  # Reusable modules (optional)
│   ├── cosmos/
│   ├── functions/
│   └── monitoring/
└── .terraform/               # Terraform working directory (gitignored)
```

## Security Best Practices

1. **Never commit** `terraform.tfvars` or `terraform.tfstate`
2. **Use Key Vault** for all secrets
3. **Enable RBAC** on all resources
4. **Use Managed Identities** instead of connection strings where possible
5. **Review** Terraform plans before applying
6. **Tag** all resources for cost tracking

## Additional Resources

- [Azure Terraform Provider Docs](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
- [Terraform Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- [Azure OpenAI Documentation](https://learn.microsoft.com/en-us/azure/ai-services/openai/)
