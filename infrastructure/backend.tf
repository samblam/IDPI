# Terraform State Backend Configuration
#
# Uncomment and configure for remote state storage in Azure Storage
# This is recommended for team environments and production deployments
#
# Prerequisites:
# 1. Create storage account:
#    az storage account create --name tfstate<random> --resource-group rg-terraform-state --location eastus --sku Standard_LRS
#
# 2. Create container:
#    az storage container create --name tfstate --account-name tfstate<random>
#
# 3. Initialize backend:
#    terraform init -backend-config="storage_account_name=tfstate<random>"

# terraform {
#   backend "azurerm" {
#     resource_group_name  = "rg-terraform-state"
#     storage_account_name = "tfstate<random>"  # Replace with your storage account name
#     container_name       = "tfstate"
#     key                  = "threatstream.tfstate"
#   }
# }

# For local development, state is stored in terraform.tfstate
# IMPORTANT: Keep terraform.tfstate secure - it contains sensitive data
# Add terraform.tfstate to .gitignore
