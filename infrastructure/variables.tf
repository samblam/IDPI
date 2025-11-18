variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"

  validation {
    condition = contains([
      "eastus", "eastus2", "westus", "westus2", "centralus",
      "northeurope", "westeurope", "uksouth", "ukwest",
      "swedencentral", "switzerlandnorth"
    ], var.location)
    error_message = "Location must be a valid Azure region with OpenAI availability."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "threatstream"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,20}$", var.project_name))
    error_message = "Project name must be 3-20 characters, lowercase alphanumeric and hyphens only."
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "ThreatStream"
    ManagedBy   = "Terraform"
    Environment = "dev"
  }
}

# Cosmos DB Variables
variable "cosmos_max_throughput" {
  description = "Maximum throughput for Cosmos DB autoscale (RU/s)"
  type        = number
  default     = 1000

  validation {
    condition     = var.cosmos_max_throughput >= 1000 && var.cosmos_max_throughput <= 100000
    error_message = "Cosmos DB throughput must be between 1000 and 100000 RU/s."
  }
}

variable "cosmos_enable_free_tier" {
  description = "Enable Cosmos DB free tier (WARNING: Only one Cosmos DB account per Azure subscription can have the free tier enabled. Enabling this on more than one account in the same subscription will cause deployment to fail.)"
  type        = bool
  default     = false
}

# Azure Functions Variables
variable "function_app_runtime" {
  description = "Azure Functions runtime version"
  type        = string
  default     = "python"
}

variable "function_app_version" {
  description = "Python runtime version"
  type        = string
  default     = "3.11"
}

variable "function_always_on" {
  description = "Keep functions warm (requires Basic or higher plan)"
  type        = bool
  default     = false
}

# Azure OpenAI Variables
variable "openai_sku" {
  description = "Azure OpenAI SKU"
  type        = string
  default     = "S0"
}

variable "openai_model_name" {
  description = "OpenAI model deployment name"
  type        = string
  default     = "gpt-4o"
}

variable "openai_model_version" {
  description = "OpenAI model version"
  type        = string
  default     = "2024-08-06"
}

variable "openai_capacity" {
  description = "OpenAI deployment capacity (tokens per minute / 1000)"
  type        = number
  default     = 30

  validation {
    condition     = var.openai_capacity >= 1 && var.openai_capacity <= 300
    error_message = "OpenAI capacity must be between 1 and 300."
  }
}

# Redis Cache Variables
variable "redis_sku" {
  description = "Redis Cache SKU (Basic, Standard, Premium)"
  type        = string
  default     = "Basic"

  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.redis_sku)
    error_message = "Redis SKU must be Basic, Standard, or Premium."
  }
}

variable "redis_capacity" {
  description = "Redis Cache capacity (0-6 for Basic/Standard, 1-5 for Premium)"
  type        = number
  default     = 0

  validation {
    condition     = var.redis_capacity >= 0 && var.redis_capacity <= 6
    error_message = "Redis capacity must be between 0 and 6."
  }
}

variable "redis_enable_non_ssl_port" {
  description = "Enable non-SSL port for Redis"
  type        = bool
  default     = false
}

# Container Apps Variables
variable "container_apps_min_replicas" {
  description = "Minimum number of API container replicas"
  type        = number
  default     = 1

  validation {
    condition     = var.container_apps_min_replicas >= 0 && var.container_apps_min_replicas <= 30
    error_message = "Min replicas must be between 0 and 30."
  }
}

variable "container_apps_max_replicas" {
  description = "Maximum number of API container replicas"
  type        = number
  default     = 10

  validation {
    condition     = var.container_apps_max_replicas >= 1 && var.container_apps_max_replicas <= 30
    error_message = "Max replicas must be between 1 and 30."
  }
}

# Monitoring Variables
variable "log_analytics_retention_days" {
  description = "Log Analytics workspace retention in days"
  type        = number
  default     = 30

  validation {
    condition     = contains([30, 60, 90, 120, 180, 270, 365, 730], var.log_analytics_retention_days)
    error_message = "Retention days must be 30, 60, 90, 120, 180, 270, 365, or 730."
  }
}

variable "application_insights_sampling_percentage" {
  description = "Application Insights sampling percentage"
  type        = number
  default     = 100

  validation {
    condition     = var.application_insights_sampling_percentage >= 0 && var.application_insights_sampling_percentage <= 100
    error_message = "Sampling percentage must be between 0 and 100."
  }
}

# Security Variables
variable "allowed_ip_addresses" {
  description = "List of IP addresses allowed to access Key Vault"
  type        = list(string)
  default     = []
}

variable "enable_key_vault_firewall" {
  description = "Enable Key Vault network restrictions"
  type        = bool
  default     = false
}
