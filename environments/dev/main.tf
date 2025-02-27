locals {
  prefix = "icp-dev"
  location = "East US"
  data_location = "United States"
}

resource "azurerm_resource_group" "resourcegroup" {
  name     = "${local.prefix}-resources"
  location = local.location
}

module "cosmos" {
  source  = "../../modules/cosmos"
  depends_on = [module.networking, module.storage, module.monitoring]
  resource_group_name = azurerm_resource_group.resourcegroup.name
  location            = local.location

  cosmosdb_account = {
    "${local.prefix}-cosmos-account" = {
        offer_type                            = "Standard"
        kind                                  = "GlobalDocumentDB"
        analytical_storage_enabled            = true   # Enable for performance insights in prod
        public_network_access_enabled         = false  # Disable public access for security in prod
        key_vault_key_id                      = "<Your Key Vault Key ID>" # Use Key Vault for security in prod
        access_key_metadata_writes_enabled    = false  # Disable unless required in prod
        network_acl_bypass_for_azure_services = false  # Stricter security in prod
        is_virtual_network_filter_enabled     = true
    }
 }

  consistency_policy = {
    consistency_level       = "Strong"  # Use Strong consistency for data integrity in prod
  }
 
  failover_locations = [
    {
      location          = local.location
      failover_priority = 0
    },
    {
      location          = "eastus"  # Add a secondary region for high availability in prod
      failover_priority = 1
    }
  ]

  capabilities = ["EnableHighAvailability"]  # Ensure high availability in prod

  virtual_network_rules = [
    {
      id = module.networking.db_subnet_id
      ignore_missing_vnet_service_endpoint = false
    }
  ]

  backup = {
    type                = "Continuous"  # Use continuous backup for better recovery in prod
    interval_in_minutes = null
    retention_in_hours  = 168  # Retain backups for 7 days in prod
  }

  cors_rules = {
    allowed_headers    = ["x-ms-meta-data*"]
    allowed_methods    = ["GET", "POST"]
    allowed_origins    = []  # Restrict CORS to specific domains in prod
    exposed_headers    = ["*"]
    max_age_in_seconds = 3600
  }

  enable_advanced_threat_protection = true
  enable_private_endpoint       = true
  virtual_network_name          = module.networking.virtual_network_name
  private_subnet_address_prefix = module.networking.pvt_subnet.address_prefix

  allowed_ip_range_cidrs = []  # Restrict access to VNet only for security in prod

  dedicated_instance_size = "Cosmos.D8s"  # Increase instance size for production workload
  dedicated_instance_count = 3  # Increase count for redundancy in prod

  log_analytics_workspace_name = module.monitoring.log_analytics_workspace_name
  storage_account_name = module.storage.storage_account_name
  
  tags = {
    ProjectName  = "fujitsu-icp"
    Environment  = "prod"  # Update environment tag to prod
  }
}

module "redis_service" {
  source              = "../../modules/redis_service"
  redis_name          = "redis-cache-dev-unique"
  location            = "eastus"
  resource_group_name            = azurerm_resource_group.resourcegroup.name
  sku_name            = "Standard"
  capacity            = 1
 # enable_non_ssl_port = false  # If needed, this setting can be enabled manually in the Azure Portal as a one-time activity.
  tags = {
    environment = "dev"
    project     = "my-project"
  }
}

module "networking" {
  source = "../../modules/networking"
  resource_group_name            = azurerm_resource_group.resourcegroup.name
  location                       = local.location
  vnetwork_name                  = "${local.prefix}-vnet"
  vnet_address_space             = ["10.1.0.0/16"]

  subnets = {
    frontend_subnet = {
      subnet_name           = "frontend_subnet"
      subnet_address_prefix = ["10.1.2.0/24"]
      service_endpoints     = ["Microsoft.Web"]

      delegation = {
        name = "webappdelegation"
        service_delegation = {
          name = "Microsoft.Web/serverFarms"
          actions = [
            "Microsoft.Network/virtualNetworks/subnets/join/action",
            "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action"
          ]
        }
      }

      nsg_inbound_rules = [
        # [name, priority, direction, access, protocol, destination_port_range, source_address_prefix, destination_address_prefix]

        # Allow HTTP traffic from Application Gateway
        ["web_allow_http", 100, "Inbound", "Allow", "Tcp", "80", "10.1.1.0/27", "*"],

        # Allow HTTPS traffic from Application Gateway
        ["web_allow_https", 101, "Inbound", "Allow", "Tcp", "443", "10.1.1.0/27", "*"],

        # Allow custom TCP port range if needed
        ["web_custom_ports", 102, "Inbound", "Allow", "Tcp", "8080-8090", "10.1.1.0/27", "*"],

        # Restrict access to Application Gateway subnet only if necessary (replace with subnet CIDR if desired)
        ["app_gateway_restricted", 110, "Inbound", "Allow", "Tcp", "80", "10.1.1.0/27", "0.0.0.0/0"]
      ]

      nsg_outbound_rules = [
        # Allow outbound NTP traffic for time sync
        ["ntp_out", 103, "Outbound", "Allow", "Udp", "123", "*", "0.0.0.0/0"],

        # Allow outbound HTTP/HTTPS if web app needs to access external resources
        ["outbound_http", 104, "Outbound", "Allow", "Tcp", "80", "*", "0.0.0.0/0"],
        ["outbound_https", 105, "Outbound", "Allow", "Tcp", "443", "*", "0.0.0.0/0"]
      ]
    }

    backend_subnet = {
      subnet_name           = "backend_subnet"
      subnet_address_prefix = ["10.1.3.0/24"]
      service_endpoints     = ["Microsoft.Web"]

      delegation = {
        name = "webappdelegation"
        service_delegation = {
          name = "Microsoft.Web/serverFarms"
          actions = [
            "Microsoft.Network/virtualNetworks/subnets/join/action",
            "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action"
          ]
        }
      }

      nsg_inbound_rules = [
        # Allow HTTP traffic for backend from frontend subnet
        ["backend_http_allow", 200, "Inbound", "Allow", "Tcp", "80", "10.1.2.0/24", "*"],

        # Allow HTTPS traffic for backend from frontend subnet
        ["backend_https_allow", 201, "Inbound", "Allow", "Tcp", "443", "10.1.2.0/24", "*"],

        # Allow custom port (e.g., 9090) for internal application communication within the VNet
        ["backend_custom_internal", 202, "Inbound", "Allow", "Tcp", "9090", "VirtualNetwork", "*"]
      ]

      nsg_outbound_rules = [
        # Allow outbound traffic to Cosmos DB service
        ["cosmos_db_outbound_allow", 300, "Outbound", "Allow", "Tcp", "443", "*", "AzureCosmosDB"],

        # Allow outbound HTTPS for any necessary API or external service access
        ["outbound_https", 301, "Outbound", "Allow", "Tcp", "443", "*", "0.0.0.0/0"]
      ]
    }

    db_subnet = {
      subnet_name           = "db_subnet"
      subnet_address_prefix = ["10.1.4.0/24"]
      service_endpoints     = ["Microsoft.AzureCosmosDB"]
      private_link_service_network_policies_enabled = true

      nsg_inbound_rules = [
        # Allow traffic from backend subnet to Cosmos DB
        ["backend_to_db_allow", 400, "Inbound", "Allow", "Tcp", "443", "10.1.3.0/24", "*"]
      ]

      nsg_outbound_rules = [
        # Allow outbound traffic to Cosmos DB service
        ["cosmos_db_outbound_allow", 401, "Outbound", "Allow", "Tcp", "443", "*", "AzureCosmosDB"]
      ]
    }

    pvt_subnet = {
      subnet_name           = "pvt_subnet"
      subnet_address_prefix = ["10.1.5.0/29"]
      service_endpoints     = ["Microsoft.Storage","Microsoft.KeyVault","Microsoft.AzureCosmosDB"]
      private_endpoint_network_policies = "NetworkSecurityGroupEnabled"
    }

    gateway_subnet = {
      subnet_name           = "gateway_subnet"
      subnet_address_prefix = ["10.1.6.0/24"]
      service_endpoints     = ["Microsoft.Storage"]

      nsg_inbound_rules = [
        # Allow Azure-managed traffic for Application Gateway V2 (required for backend health monitoring and management)
        ["appgw_v2_azure_traffic", 200, "Inbound", "Allow", "Tcp", "65200-65535", "GatewayManager", "*"],

        # Allow HTTP traffic from any source to the Application Gateway
        ["appgw_http_allow", 201, "Inbound", "Allow", "Tcp", "80", "*", "*"],

        # Allow HTTPS traffic from Azure Load Balancer to the Application Gateway
        ["appgw_https_allow", 202, "Inbound", "Allow", "Tcp", "443", "AzureLoadBalancer", "*"],

        # Allow custom port (9090) for internal communication within the VNet to the Application Gateway
        ["appgw_custom_internal", 203, "Inbound", "Allow", "Tcp", "9090", "VirtualNetwork", "*"]
      ]

      nsg_outbound_rules = [
      ]
    }
  }

  tags = {
    ProjectName = "fujitsu-icp"
    Environment = "dev"
  }
}

module "storage" {
  source = "../../modules/storage"
  resource_group_name = azurerm_resource_group.resourcegroup.name
  location            = local.location
  
  storage_account_name  = "${local.prefix}storage"
  account_kind = "StorageV2"
  access_tier = "Hot"
  skuname = "Standard_ZRS"

  enable_advanced_threat_protection = true

  # containers_list = [
  #  { name = "blobcontainer251", access_type = "blob" }
  # ]

  # Configure managed identities to access Azure Storage (Optional)
  # Possible types are `SystemAssigned`, `UserAssigned` and `SystemAssigned, UserAssigned`.
  # managed_identity_type = "UserAssigned"
  # managed_identity_ids  = [for k in azurerm_user_assigned_identity.example : k.id]

  # lifecycles = [
  #   {
  #     prefix_match               = ["blobcontainer251"]
  #     tier_to_cool_after_days    = 0
  #     tier_to_archive_after_days = 50
  #     delete_after_days          = 100
  #     snapshot_delete_after_days = 30
  #   }
  # ]

  tags = {
    ProjectName  = "fujitsu-icp"
    Environment  = "dev"
  }
}

module "frontend-app-service" {
  source  = "../../modules/app_service"
  depends_on = [module.networking, module.storage]
  resource_group_name = azurerm_resource_group.resourcegroup.name
  location            = local.location

  app_service_plan_name = "${local.prefix}-frontendserviceplan"
  service_plan = {
    os_type = "Linux"
    sku_name = "B1"
  }

  app_service_name       = "${local.prefix}-fe-flutter-app"
  enable_client_affinity = true
  enable_https           = true

  site_config = {
    always_on                 = true
    ftps_state                = "FtpsOnly"
    http2_enabled             = true
  }

  application_stack = {
    type    = "NODE"
    version = "20-lts"
  }

  # (Optional) A key-value pair of Application Settings
  app_settings = {
    APPINSIGHTS_PROFILERFEATURE_VERSION             = "1.0.0"
    APPINSIGHTS_SNAPSHOTFEATURE_VERSION             = "1.0.0"
    DiagnosticServices_EXTENSION_VERSION            = "~3"
    InstrumentationEngine_EXTENSION_VERSION         = "disabled"
    SnapshotDebugger_EXTENSION_VERSION              = "disabled"
    XDT_MicrosoftApplicationInsights_BaseExtensions = "disabled"
    XDT_MicrosoftApplicationInsights_Java           = "1"
    XDT_MicrosoftApplicationInsights_Mode           = "recommended"
    XDT_MicrosoftApplicationInsights_NodeJS         = "1"
    XDT_MicrosoftApplicationInsights_PreemptSdk     = "disabled"
  }

  enable_backup        = true
  storage_account_name = module.storage.storage_account_name
  storage_container_name = "frontend-appservice-backup"
  backup_settings = {
    enabled                  = true
    name                     = "DefaultBackup"
    frequency_interval       = 1
    frequency_unit           = "Day"
    retention_period_days    = 90
  }

  app_insights_name = "frontendapp"

  enable_vnet_integration = true
  subnet_id = module.networking.frontend_subnet_id

  tags = {
    ProjectName  = "fujitsu-icp"
    Environment  = "dev"
  }
}

module "api_management" {
  source              = "../../modules/api_management"
  depends_on          = [module.frontend-app-service]
  resource_group_name = azurerm_resource_group.resourcegroup.name
  location            = local.location
  api_management_name = "${local.prefix}-api-management-v2"
  publisher_name      = "Rock Paper Panda"
  publisher_email     = "team@rockpaperpanda.com"
  sku_name            = "Developer_1"
}

module "communication_service" {
  source                  = "../../modules/communication_service"
  depends_on = [module.backend-app-service]
  resource_group_name = azurerm_resource_group.resourcegroup.name
  location            = local.location
  communication_service_name = "${local.prefix}-communication-svc"
  data_location           = local.data_location
}

module "backend-app-service" {
  source  = "../../modules/app_service"
  depends_on = [module.networking, module.storage]
  resource_group_name = azurerm_resource_group.resourcegroup.name
  location            = local.location

  app_service_plan_name = "${local.prefix}-backendserviceplan"
  service_plan = {
    os_type = "Linux"
    sku_name = "B1"
  }

  app_service_name       = "${local.prefix}-be-python-app"
  enable_client_affinity = true
  enable_https           = true

  site_config = {
    always_on                 = true
    ftps_state                = "FtpsOnly"
    http2_enabled             = true
  }

  application_stack = {
    type    = "PYTHON"
    version = "3.9"
  }

  # (Optional) A key-value pair of Application Settings
  app_settings = {
    APPINSIGHTS_PROFILERFEATURE_VERSION             = "1.0.0"
    APPINSIGHTS_SNAPSHOTFEATURE_VERSION             = "1.0.0"
    DiagnosticServices_EXTENSION_VERSION            = "~3"
    InstrumentationEngine_EXTENSION_VERSION         = "disabled"
    SnapshotDebugger_EXTENSION_VERSION              = "disabled"
    XDT_MicrosoftApplicationInsights_BaseExtensions = "disabled"
    XDT_MicrosoftApplicationInsights_Java           = "1"
    XDT_MicrosoftApplicationInsights_Mode           = "recommended"
    XDT_MicrosoftApplicationInsights_NodeJS         = "1"
    XDT_MicrosoftApplicationInsights_PreemptSdk     = "disabled"
  }

  enable_backup        = true
  storage_account_name = module.storage.storage_account_name
  storage_container_name = "backend-appservice-backup"
  backup_settings = {
    enabled                  = true
    name                     = "DefaultBackup"
    frequency_interval       = 1
    frequency_unit           = "Day"
    retention_period_days    = 90
  }

  app_insights_name = "backendapp"
  enable_vnet_integration = true
  subnet_id = module.networking.backend_subnet_id
 
  tags = {
    ProjectName  = "fujitsu-icp"
    Environment  = "dev"
  }
}

module "key-vault" {
  source  = "../../modules/key_vault"
  depends_on = [module.networking, module.storage]
  resource_group_name = azurerm_resource_group.resourcegroup.name
  location            = local.location

  key_vault_name             = "${local.prefix}-keyvault"
  key_vault_sku_pricing_tier = "premium"

  # Once `Purge Protection` has been Enabled it's not possible to Disable it
  # Deleting the Key Vault with `Purge Protection` enabled will schedule the Key Vault to be deleted
  # The default retention period is 90 days, possible values are from 7 to 90 days
  # use `soft_delete_retention_days` to set the retention period
  enable_purge_protection = false
  soft_delete_retention_days = 90

  # Access policies for users, you can provide list of Azure AD users and set permissions.
  # Make sure to use list of user principal names of Azure AD users.
  # access_policies = [
  #   {
  #     azure_ad_user_principal_names = [""]
  #     key_permissions               = ["Get", "List"]
  #     secret_permissions            = ["Get", "List"]
  #     certificate_permissions       = ["Get", "Import", "List"]
  #     storage_permissions           = ["Backup", "Get", "List", "Recover"]
  #   },

  #   # Access policies for AD Groups
  #   # to enable this feature, provide a list of Azure AD groups and set permissions as required.
  #   {
  #     azure_ad_group_names    = [""]
  #     key_permissions         = ["Get", "List"]
  #     secret_permissions      = ["Get", "List"]
  #     certificate_permissions = ["Get", "Import", "List"]
  #     storage_permissions     = ["Backup", "Get", "List", "Recover"]
  #   },

  #   # Access policies for Azure AD Service Principlas
  #   # To enable this feature, provide a list of Azure AD SPN and set permissions as required.
  #   {
  #     azure_ad_service_principal_names = [""]
  #     key_permissions                  = ["Get", "List"]
  #     certificate_permissions          = ["Get", "Import", "List"]
  #     storage_permissions              = ["Backup", "Get", "List", "Recover"]
  #   }
  # ]

  # Create a required Secrets as per your need.
  # When you Add `usernames` with empty password this module creates a strong random password
  # use .tfvars file to manage the secrets as variables to avoid security issues.
  secrets = {
    "message" = "Hello, world!"
    "vmpass"  = ""
  }

  enable_private_endpoint       = true
  virtual_network_name          = module.networking.virtual_network_name
  private_subnet_address_prefix = module.networking.pvt_subnet.address_prefix
  log_analytics_workspace_name = module.monitoring.log_analytics_workspace_name
  storage_account_name = module.storage.storage_account_name

  tags = {
    ProjectName  = "fujitsu-icp"
    Environment  = "dev"
  }
}

module "application-gateway" {
  source     = "../../modules/application_gateway"
  depends_on = [module.networking, module.frontend-app-service, module.storage, module.monitoring]

  resource_group_name = azurerm_resource_group.resourcegroup.name
  location            = local.location

  virtual_network_name = module.networking.virtual_network_name
  subnet_name          = module.networking.gateway_subnet
  app_gateway_name     = "testgateway"

  sku = {
    name = "Standard_v2"
    tier = "Standard_v2"
  }

  autoscale_configuration = {
    min_capacity = 1
    max_capacity = 5
  }

  backend_address_pools = [
    {
      name  = "appgw-testgateway-eastus-bapool01"
      fqdns = [module.frontend-app-service.default_hostname]
    }
  ]

  backend_http_settings = [
    {
      name                  = "appgw-testgateway-eastus-be-http-set1"
      cookie_based_affinity = "Disabled"
      path                  = "/"
      enable_https          = true
      request_timeout       = 30
      host_name             = module.frontend-app-service.default_hostname
      probe_name            = "appgw-testgateway-eastus-probe1"
      connection_draining = {
        enable_connection_draining = true
        drain_timeout_sec          = 300
      }
    },
    {
      name                  = "appgw-testgateway-eastus-be-http-set2"
      cookie_based_affinity = "Enabled"
      path                  = "/"
      enable_https          = false
      request_timeout       = 30
    }
  ]

  http_listeners = [
    {
      name = "appgw-testgateway-eastus-be-htln01"
      # ssl_certificate_name = "appgw-testgateway-eastus-ssl01"
      host_name = null
    }
  ]

  request_routing_rules = [
    {
      name                       = "appgw-testgateway-eastus-be-rqrt"
      rule_type                  = "Basic"
      http_listener_name         = "appgw-testgateway-eastus-be-htln01"
      backend_address_pool_name  = "appgw-testgateway-eastus-bapool01"
      backend_http_settings_name = "appgw-testgateway-eastus-be-http-set1"
      priority                   = 1
    }
  ]

  # ssl_certificates = [{
  #   name     = "appgw-testgateway-eastus-ssl01"
  #   data     = "./keyBag.pfx"
  #   password = "P@$$w0rd123"
  # }]

  health_probes = [
    {
      name                = "appgw-testgateway-eastus-probe1"
      host                = module.frontend-app-service.default_hostname
      interval            = 30
      path                = "/"
      port                = 443
      timeout             = 30
      unhealthy_threshold = 3
    }
  ]

  # A list with a single user managed identity id to be assigned to access Keyvault
  # identity_ids = ["${azurerm_user_assigned_identity.example.id}"]

  log_analytics_workspace_name = module.monitoring.log_analytics_workspace_name
  storage_account_name = module.storage.storage_account_name

  # Adding TAG's to Azure resources
  tags = {
    ProjectName = "fujitsu-icp"
    Environment = "dev"
  }
}

module "monitoring" {
  source = "../../modules/monitoring"
  resource_group_name = azurerm_resource_group.resourcegroup.name
  location            = local.location

  log_analytics_workspace_name = "${local.prefix}-logws"
  sku = "PerGB2018"
  retention_in_days = "30"
}
