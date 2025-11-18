# ==============================================================================
# Data Sources
# ==============================================================================

data "azurerm_client_config" "current" {}

# Random suffix for globally unique names
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  # Naming convention: {resource-type}-{project}-{environment}-{random}
  resource_prefix = "${var.project_name}-${var.environment}"
  unique_suffix   = random_string.suffix.result

  common_tags = merge(var.tags, {
    Environment = var.environment
    Terraform   = "true"
  })
}

# ==============================================================================
# Resource Group
# ==============================================================================

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.resource_prefix}"
  location = var.location
  tags     = local.common_tags
}

# ==============================================================================
# Cosmos DB
# ==============================================================================

resource "azurerm_cosmosdb_account" "main" {
  name                = "cosmos-${local.resource_prefix}-${local.unique_suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  enable_free_tier         = var.cosmos_enable_free_tier
  enable_automatic_failover = false

  consistency_policy {
    consistency_level       = "Session"
    max_interval_in_seconds = 5
    max_staleness_prefix    = 100
  }

  geo_location {
    location          = azurerm_resource_group.main.location
    failover_priority = 0
  }

  capabilities {
    name = "EnableServerless"
  }

  backup {
    type = "Continuous"
  }

  tags = local.common_tags
}

resource "azurerm_cosmosdb_sql_database" "main" {
  name                = "threatstream"
  resource_group_name = azurerm_cosmosdb_account.main.resource_group_name
  account_name        = azurerm_cosmosdb_account.main.name
}

# Raw indicators container
resource "azurerm_cosmosdb_sql_container" "raw_indicators" {
  name                  = "raw_indicators"
  resource_group_name   = azurerm_cosmosdb_account.main.resource_group_name
  account_name          = azurerm_cosmosdb_account.main.name
  database_name         = azurerm_cosmosdb_sql_database.main.name
  partition_key_path    = "/source"
  partition_key_version = 1

  default_ttl = 2592000 # 30 days

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }

    excluded_path {
      path = "/\"_etag\"/?"
    }
  }
}

# Normalized indicators container
resource "azurerm_cosmosdb_sql_container" "normalized_indicators" {
  name                  = "normalized_indicators"
  resource_group_name   = azurerm_cosmosdb_account.main.resource_group_name
  account_name          = azurerm_cosmosdb_account.main.name
  database_name         = azurerm_cosmosdb_sql_database.main.name
  partition_key_path    = "/indicator_type"
  partition_key_version = 1

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }

    included_path {
      path = "/indicator_value/?"
    }

    included_path {
      path = "/confidence_score/?"
    }
  }

  unique_key {
    paths = ["/indicator_value"]
  }
}

# Enriched indicators container
resource "azurerm_cosmosdb_sql_container" "enriched_indicators" {
  name                  = "enriched_indicators"
  resource_group_name   = azurerm_cosmosdb_account.main.resource_group_name
  account_name          = azurerm_cosmosdb_account.main.name
  database_name         = azurerm_cosmosdb_sql_database.main.name
  partition_key_path    = "/indicator_type"
  partition_key_version = 1

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }

    included_path {
      path = "/enrichment/severity/?"
    }

    included_path {
      path = "/confidence_score/?"
    }
  }
}

# Relationships container
resource "azurerm_cosmosdb_sql_container" "relationships" {
  name                  = "relationships"
  resource_group_name   = azurerm_cosmosdb_account.main.resource_group_name
  account_name          = azurerm_cosmosdb_account.main.name
  database_name         = azurerm_cosmosdb_sql_database.main.name
  partition_key_path    = "/source_id"
  partition_key_version = 1

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }
  }
}

# ==============================================================================
# Storage Account (for Azure Functions)
# ==============================================================================

resource "azurerm_storage_account" "functions" {
  name                     = "stfunc${var.project_name}${var.environment}${local.unique_suffix}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  tags = local.common_tags
}

# ==============================================================================
# Application Insights & Log Analytics
# ==============================================================================

resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${local.resource_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_analytics_retention_days

  tags = local.common_tags
}

resource "azurerm_application_insights" "main" {
  name                = "appi-${local.resource_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  sampling_percentage = var.application_insights_sampling_percentage

  tags = local.common_tags
}

# ==============================================================================
# Azure Functions
# ==============================================================================

resource "azurerm_service_plan" "functions" {
  name                = "plan-${local.resource_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption plan

  tags = local.common_tags
}

resource "azurerm_linux_function_app" "main" {
  name                = "func-${local.resource_prefix}-${local.unique_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key
  service_plan_id            = azurerm_service_plan.functions.id

  site_config {
    application_stack {
      python_version = var.function_app_version
    }

    application_insights_key               = azurerm_application_insights.main.instrumentation_key
    application_insights_connection_string = azurerm_application_insights.main.connection_string

    cors {
      allowed_origins = ["*"]
    }
  }

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME       = "python"
    COSMOS_ENDPOINT                = azurerm_cosmosdb_account.main.endpoint
    COSMOS_KEY                     = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.cosmos_key.id})"
    COSMOS_DATABASE                = azurerm_cosmosdb_sql_database.main.name
    OPENAI_ENDPOINT                = azurerm_cognitive_account.openai.endpoint
    OPENAI_API_KEY                 = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.openai_key.id})"
    OPENAI_MODEL                   = "${var.openai_model_name}-${var.openai_model_version}"
    REDIS_HOST                     = azurerm_redis_cache.main.hostname
    REDIS_PORT                     = azurerm_redis_cache.main.ssl_port
    REDIS_PASSWORD                 = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.redis_key.id})"
    KEY_VAULT_URI                  = azurerm_key_vault.main.vault_uri
    APPINSIGHTS_INSTRUMENTATIONKEY = azurerm_application_insights.main.instrumentation_key
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags
}

# ==============================================================================
# Azure OpenAI
# ==============================================================================

resource "azurerm_cognitive_account" "openai" {
  name                = "cog-${local.resource_prefix}-${local.unique_suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  kind                = "OpenAI"
  sku_name            = var.openai_sku

  custom_subdomain_name = "openai-${local.resource_prefix}-${local.unique_suffix}"

  tags = local.common_tags
}

# NOTE: Azure OpenAI model versions may change over time and can be deprecated.
# Before deployment, verify that the model version specified in variables is currently
# supported in your Azure region by checking: https://learn.microsoft.com/azure/ai-services/openai/concepts/models
resource "azurerm_cognitive_deployment" "gpt4o" {
  name                 = "${var.openai_model_name}-${var.openai_model_version}"
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = "OpenAI"
    name    = var.openai_model_name
    version = var.openai_model_version
  }

  scale {
    type     = "Standard"
    capacity = var.openai_capacity
  }
}

# ==============================================================================
# Redis Cache
# ==============================================================================

resource "azurerm_redis_cache" "main" {
  name                = "redis-${local.resource_prefix}-${local.unique_suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  capacity            = var.redis_capacity
  family              = var.redis_sku == "Premium" ? "P" : "C"
  sku_name            = var.redis_sku
  enable_non_ssl_port = var.redis_enable_non_ssl_port
  minimum_tls_version = "1.2"

  redis_configuration {
    enable_authentication = true
  }

  tags = local.common_tags
}

# ==============================================================================
# Container Registry
# ==============================================================================

resource "azurerm_container_registry" "main" {
  name                = "cr${var.project_name}${var.environment}${local.unique_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = true

  tags = local.common_tags
}

# ==============================================================================
# Container Apps Environment
# ==============================================================================

resource "azurerm_container_app_environment" "main" {
  name                       = "cae-${local.resource_prefix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  tags = local.common_tags
}

resource "azurerm_container_app" "api" {
  name                         = "ca-${local.resource_prefix}-api"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  template {
    min_replicas = var.container_apps_min_replicas
    max_replicas = var.container_apps_max_replicas

    container {
      name   = "threatstream-api"
      image  = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest" # Placeholder - update with your image
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name  = "COSMOS_ENDPOINT"
        value = azurerm_cosmosdb_account.main.endpoint
      }

      env {
        name        = "COSMOS_KEY"
        secret_name = "cosmos-key"
      }

      env {
        name  = "COSMOS_DATABASE"
        value = azurerm_cosmosdb_sql_database.main.name
      }

      env {
        name  = "REDIS_HOST"
        value = azurerm_redis_cache.main.hostname
      }

      env {
        name  = "REDIS_PORT"
        value = tostring(azurerm_redis_cache.main.ssl_port)
      }

      env {
        name        = "REDIS_PASSWORD"
        secret_name = "redis-password"
      }

      env {
        name  = "APPINSIGHTS_INSTRUMENTATIONKEY"
        value = azurerm_application_insights.main.instrumentation_key
      }
    }
  }

  secret {
    name  = "cosmos-key"
    value = azurerm_cosmosdb_account.main.primary_key
  }

  secret {
    name  = "redis-password"
    value = azurerm_redis_cache.main.primary_access_key
  }

  ingress {
    external_enabled = true
    target_port      = 8000

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags
}

# ==============================================================================
# Key Vault
# ==============================================================================

resource "azurerm_key_vault" "main" {
  name                       = "kv-${var.project_name}-${var.environment}-${local.unique_suffix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  enable_rbac_authorization = false

  network_acls {
    default_action = var.enable_key_vault_firewall ? "Deny" : "Allow"
    bypass         = "AzureServices"
    ip_rules       = var.allowed_ip_addresses
  }

  tags = local.common_tags
}

# Key Vault Access Policy for current user
resource "azurerm_key_vault_access_policy" "user" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = [
    "Get", "List", "Set", "Delete", "Purge", "Recover"
  ]
}

# Key Vault Access Policy for Functions
resource "azurerm_key_vault_access_policy" "functions" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_linux_function_app.main.identity[0].principal_id

  secret_permissions = [
    "Get", "List"
  ]
}

# Key Vault Access Policy for Container App
resource "azurerm_key_vault_access_policy" "container_app" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_container_app.api.identity[0].principal_id

  secret_permissions = [
    "Get", "List"
  ]
}

# Store secrets in Key Vault
resource "azurerm_key_vault_secret" "cosmos_key" {
  name         = "COSMOS-KEY"
  value        = azurerm_cosmosdb_account.main.primary_key
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_key_vault_access_policy.user]
}

resource "azurerm_key_vault_secret" "openai_key" {
  name         = "OPENAI-API-KEY"
  value        = azurerm_cognitive_account.openai.primary_access_key
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_key_vault_access_policy.user]
}

resource "azurerm_key_vault_secret" "redis_key" {
  name         = "REDIS-PASSWORD"
  value        = azurerm_redis_cache.main.primary_access_key
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_key_vault_access_policy.user]
}
