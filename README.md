# Fujitsu
Terraform files to provision resources on Azure infrastructure for development environment

# Terraform Project Structure

This Terraform project is organized into modules for various Azure resources and environments. Below is an overview of the folder structure:

```bash
├── modules/                    # Reusable modules for different Azure resources
│   ├── app_service/            # Module for Azure App Service
│   │   ├── main.tf             # Defines the resource configurations
│   │   ├── variables.tf        # Input variables for the module
│   │   ├── outputs.tf          # Output variables for the module
│   ├── cosmos/                 # Module for Azure CosmosDB
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   ├── api_management/         # Module for Azure API Management
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   ├── networking/             # Module for Networking
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   ├── application_gateway/    # Module for Application Gateway
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   ├── key_vault/              # Module for Key Vault
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   ├── storage/                # Module for Storage
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   ├── azuread_b2c/            # Module for Azure AD B2C
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   ├── monitoring/             # Module for Monitoring
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│
└── environments/               # Environment-specific configurations
    ├── dev/                    # Development environment
    │   ├── main.tf
    │   ├── variables.tf
    │   ├── outputs.tf
	└── prod/                   # Production environment
        ├── main.tf
        ├── variables.tf
        ├── outputs.tf
```
# How to Use

**Modules:**  
Each folder under `modules/` contains reusable Terraform code for provisioning specific Azure services. These modules are parameterized using `variables.tf` and produce outputs defined in `outputs.tf`.

**Environments:**  
The `environments/` directory contains configurations for different deployment environments, such as `dev` and `prod`. Each environment folder can call the required modules for that environment.

# Instructions

1. Navigate to the environment folder you want to deploy (`dev` or `prod`).

2. Run the following Terraform commands:

   ```bash
     	 terraform init
     	 terraform plan
     	 terraform apply
   ```

3. Adjust the variables.tf in the respective environment to match your configuration needs.
