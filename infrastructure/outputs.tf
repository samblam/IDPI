# ==============================================================================
# Resource Group Outputs
# ==============================================================================

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_location" {
  description = "Location of the resource group"
  value       = azurerm_resource_group.main.location
}

# ==============================================================================
# Cosmos DB Outputs
# ==============================================================================

output "cosmos_endpoint" {
  description = "Cosmos DB endpoint URL"
  value       = azurerm_cosmosdb_account.main.endpoint
}

output "cosmos_database_name" {
  description = "Cosmos DB database name"
  value       = azurerm_cosmosdb_sql_database.main.name
}

output "cosmos_connection_string" {
  description = "Cosmos DB primary connection string"
  value       = azurerm_cosmosdb_account.main.primary_sql_connection_string
  sensitive   = true
}

output "cosmos_key" {
  description = "Cosmos DB primary key"
  value       = azurerm_cosmosdb_account.main.primary_key
  sensitive   = true
}

# ==============================================================================
# Azure Functions Outputs
# ==============================================================================

output "function_app_name" {
  description = "Name of the Azure Function App"
  value       = azurerm_linux_function_app.main.name
}

output "function_app_default_hostname" {
  description = "Default hostname of the Function App"
  value       = azurerm_linux_function_app.main.default_hostname
}

output "function_app_url" {
  description = "HTTPS URL of the Function App"
  value       = "https://${azurerm_linux_function_app.main.default_hostname}"
}

output "function_app_identity_principal_id" {
  description = "Principal ID of the Function App managed identity"
  value       = azurerm_linux_function_app.main.identity[0].principal_id
}

# ==============================================================================
# Azure OpenAI Outputs
# ==============================================================================

output "openai_endpoint" {
  description = "Azure OpenAI endpoint URL"
  value       = azurerm_cognitive_account.openai.endpoint
}

output "openai_key" {
  description = "Azure OpenAI primary access key"
  value       = azurerm_cognitive_account.openai.primary_access_key
  sensitive   = true
}

output "openai_deployment_name" {
  description = "Azure OpenAI model deployment name"
  value       = azurerm_cognitive_deployment.gpt4o.name
}

# ==============================================================================
# Redis Cache Outputs
# ==============================================================================

output "redis_hostname" {
  description = "Redis Cache hostname"
  value       = azurerm_redis_cache.main.hostname
}

output "redis_ssl_port" {
  description = "Redis Cache SSL port"
  value       = azurerm_redis_cache.main.ssl_port
}

output "redis_primary_key" {
  description = "Redis Cache primary access key"
  value       = azurerm_redis_cache.main.primary_access_key
  sensitive   = true
}

output "redis_connection_string" {
  description = "Redis Cache connection string"
  value       = "${azurerm_redis_cache.main.hostname}:${azurerm_redis_cache.main.ssl_port},password=${azurerm_redis_cache.main.primary_access_key},ssl=True,abortConnect=False"
  sensitive   = true
}

# ==============================================================================
# Container Registry Outputs
# ==============================================================================

output "container_registry_name" {
  description = "Name of the Container Registry"
  value       = azurerm_container_registry.main.name
}

output "container_registry_login_server" {
  description = "Login server URL for Container Registry"
  value       = azurerm_container_registry.main.login_server
}

output "container_registry_admin_username" {
  description = "Admin username for Container Registry"
  value       = azurerm_container_registry.main.admin_username
}

output "container_registry_admin_password" {
  description = "Admin password for Container Registry"
  value       = azurerm_container_registry.main.admin_password
  sensitive   = true
}

# ==============================================================================
# Container Apps Outputs
# ==============================================================================

output "container_app_api_name" {
  description = "Name of the API Container App"
  value       = azurerm_container_app.api.name
}

output "container_app_api_url" {
  description = "HTTPS URL of the API Container App"
  value       = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}

output "container_app_api_fqdn" {
  description = "Fully qualified domain name of the API Container App"
  value       = azurerm_container_app.api.ingress[0].fqdn
}

# ==============================================================================
# Key Vault Outputs
# ==============================================================================

output "key_vault_name" {
  description = "Name of the Key Vault"
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.main.vault_uri
}

# ==============================================================================
# Application Insights Outputs
# ==============================================================================

output "application_insights_instrumentation_key" {
  description = "Application Insights instrumentation key"
  value       = azurerm_application_insights.main.instrumentation_key
  sensitive   = true
}

output "application_insights_connection_string" {
  description = "Application Insights connection string"
  value       = azurerm_application_insights.main.connection_string
  sensitive   = true
}

output "application_insights_app_id" {
  description = "Application Insights application ID"
  value       = azurerm_application_insights.main.app_id
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID"
  value       = azurerm_log_analytics_workspace.main.id
}

# ==============================================================================
# Summary Outputs
# ==============================================================================

output "deployment_summary" {
  description = "Summary of deployed resources"
  value = {
    resource_group     = azurerm_resource_group.main.name
    location           = azurerm_resource_group.main.location
    environment        = var.environment
    cosmos_db          = azurerm_cosmosdb_account.main.name
    function_app       = azurerm_linux_function_app.main.name
    openai_account     = azurerm_cognitive_account.openai.name
    redis_cache        = azurerm_redis_cache.main.name
    container_registry = azurerm_container_registry.main.name
    container_app_api  = azurerm_container_app.api.name
    key_vault          = azurerm_key_vault.main.name
  }
}

output "next_steps" {
  description = "Next steps after deployment"
  value = <<-EOT
    Deployment complete! Next steps:

    1. Add threat intelligence API keys to Key Vault:
       az keyvault secret set --vault-name ${azurerm_key_vault.main.name} --name "OTX-API-KEY" --value "your-otx-key"
       az keyvault secret set --vault-name ${azurerm_key_vault.main.name} --name "ABUSEIPDB-API-KEY" --value "your-abuseipdb-key"

    2. Build and push API container image:
       az acr login --name ${azurerm_container_registry.main.name}
       docker build -t ${azurerm_container_registry.main.login_server}/threatstream-api:latest ./api
       docker push ${azurerm_container_registry.main.login_server}/threatstream-api:latest

    3. Deploy Azure Functions code:
       cd ingestion
       func azure functionapp publish ${azurerm_linux_function_app.main.name}

    4. Update Container App with your image:
       az containerapp update --name ${azurerm_container_app.api.name} \
         --resource-group ${azurerm_resource_group.main.name} \
         --image ${azurerm_container_registry.main.login_server}/threatstream-api:latest

    5. Test the deployment:
       Function App: https://${azurerm_linux_function_app.main.default_hostname}
       API: https://${azurerm_container_app.api.ingress[0].fqdn}

    6. Monitor in Azure Portal:
       Application Insights: ${azurerm_application_insights.main.name}
       Log Analytics: ${azurerm_log_analytics_workspace.main.name}
  EOT
}
