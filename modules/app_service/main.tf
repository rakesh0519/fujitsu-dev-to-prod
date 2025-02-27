#---------------------------------
# Local declarations
#---------------------------------
locals {
  # Default configuration for Site config block
  default_site_config = {
    always_on = "true"
}

  # Enabling the App Insights on app service - default configuration for agent
  app_insights = try(azurerm_application_insights.main.0, {})

  default_app_settings = var.application_insights_enabled ? {
    APPLICATION_INSIGHTS_IKEY                  = try(local.app_insights.instrumentation_key, "")
    APPINSIGHTS_INSTRUMENTATIONKEY             = try(local.app_insights.instrumentation_key, "")
    APPLICATIONINSIGHTS_CONNECTION_STRING      = try(local.app_insights.connection_string, "")
    ApplicationInsightsAgent_EXTENSION_VERSION = "~2"
  } : {}

  # App service IP Address, Subnet_ids and Service_Tag restrictions
  ip_address = [for ip_address in var.ips_allowed : {
    name                      = "ip_restriction_cidr_${join("", [1, index(var.ips_allowed, ip_address)])}"
    ip_address                = ip_address
    virtual_network_subnet_id = null
    service_tag               = null
    subnet_id                 = null
    priority                  = join("", [1, index(var.ips_allowed, ip_address)])
    action                    = "Allow"
  }]

  subnets = [for subnet in var.subnet_ids_allowed : {
    name                      = "ip_restriction_subnet_${join("", [1, index(var.subnet_ids_allowed, subnet)])}"
    ip_address                = null
    virtual_network_subnet_id = subnet
    service_tag               = null
    subnet_id                 = subnet
    priority                  = join("", [1, index(var.subnet_ids_allowed, subnet)])
    action                    = "Allow"
  }]

  service_tags = [for service_tag in var.service_tags_allowed : {
    name                      = "service_tag_restriction_${join("", [1, index(var.service_tags_allowed, service_tag)])}"
    ip_address                = null
    virtual_network_subnet_id = null
    service_tag               = service_tag
    subnet_id                 = null
    priority                  = join("", [1, index(var.service_tags_allowed, service_tag)])
    action                    = "Allow"
  }]

  # App service SCM IP Address, SCM Subnet_ids andSCM  Service_Tag restrictions
  scm_ip_address = [for ip_address in var.scm_ips_allowed : {
    name                      = "scm_ip_restriction_cidr_${join("", [1, index(var.scm_ips_allowed, ip_address)])}"
    ip_address                = ip_address
    virtual_network_subnet_id = null
    service_tag               = null
    subnet_id                 = null
    priority                  = join("", [1, index(var.scm_ips_allowed, ip_address)])
    action                    = "Allow"
  }]

  scm_subnets = [for subnet in var.scm_subnet_ids_allowed : {
    name                      = "scm_ip_restriction_subnet_${join("", [1, index(var.scm_subnet_ids_allowed, subnet)])}"
    ip_address                = null
    virtual_network_subnet_id = subnet
    service_tag               = null
    subnet_id                 = subnet
    priority                  = join("", [1, index(var.scm_subnet_ids_allowed, subnet)])
    action                    = "Allow"
  }]

  scm_service_tags = [for service_tag in var.scm_service_tags_allowed : {
    name                      = "scm_service_tag_restriction_${join("", [1, index(var.scm_service_tags_allowed, service_tag)])}"
    ip_address                = null
    virtual_network_subnet_id = null
    service_tag               = service_tag
    subnet_id                 = null
    priority                  = join("", [1, index(var.scm_service_tags_allowed, service_tag)])
    action                    = "Allow"
  }]

}

data "azurerm_client_config" "main" {}

#---------------------------------------------------------
# Generating Storage SAS URL 
#----------------------------------------------------------
data "azurerm_storage_account" "storeacc" {
  count               = var.enable_backup ? 1 : 0
  name                = var.storage_account_name
  resource_group_name = var.resource_group_name
}

resource "azurerm_storage_container" "storcont" {
  count                 = var.enable_backup ? 1 : 0
  name                  = var.storage_container_name == null ? "appservice-backup" : var.storage_container_name
  storage_account_name  = data.azurerm_storage_account.storeacc[count.index].name
  container_access_type = "private"
}

resource "time_rotating" "main" {
  count            = var.enable_backup ? 1 : 0
  rotation_rfc3339 = var.password_end_date
  rotation_years   = var.password_rotation_in_years

  triggers = {
    end_date = var.password_end_date
    years    = var.password_rotation_in_years
  }
}

data "azurerm_storage_account_blob_container_sas" "main" {
  count             = var.enable_backup ? 1 : 0
  connection_string = data.azurerm_storage_account.storeacc.0.primary_connection_string
  container_name    = azurerm_storage_container.storcont.0.name
  https_only        = true

  start  = timestamp()
  expiry = time_rotating.main.0.rotation_rfc3339

  permissions {
    read   = true
    add    = true
    create = true
    write  = true
    delete = true
    list   = true
  }

  cache_control       = "max-age=5"
  content_disposition = "inline"
  content_encoding    = "deflate"
  content_language    = "en-US"
  content_type        = "application/json"
}

#---------------------------------------------------------
# App Service Plan definition - Default is "true"
#----------------------------------------------------------
resource "azurerm_service_plan" "main" {
  name                = var.app_service_plan_name == "" ? format("plan-%s", lower(replace(var.app_service_name, "/[[:^alnum:]]/", ""))) : var.app_service_plan_name
  resource_group_name = var.resource_group_name
  location            = var.location
  os_type             = var.service_plan.os_type
  sku_name            = var.service_plan.sku_name
  tags                = merge({ "ResourceName" = format("%s", var.app_service_plan_name) }, var.tags)
}

#---------------------------------------------------------
# App Service Definitions  - Default is "true"
#----------------------------------------------------------
resource "azurerm_linux_web_app" "main" {
  name                    = lower(format("app-%s", var.app_service_name))
  resource_group_name     = var.resource_group_name
  location                = var.location
  service_plan_id         = azurerm_service_plan.main.id
  client_affinity_enabled = var.enable_client_affinity
  https_only              = var.enable_https
  tags                    = merge({ "ResourceName" = lower(format("app-%s", var.app_service_name)) }, var.tags, )
  # app_settings            = merge(local.default_app_settings, var.app_settings)

  dynamic "site_config" {
    for_each = [merge(local.default_site_config, var.site_config)]

    content {
      always_on                   = lookup(site_config.value, "always_on", false)
      api_management_api_id       = lookup(site_config.value, "api_management_api_id", null)
      app_command_line            = lookup(site_config.value, "app_command_line", null)
      default_documents           = lookup(site_config.value, "default_documents", null)
      ftps_state                  = lookup(site_config.value, "ftps_state", "FtpsOnly")
      health_check_path           = lookup(site_config.value, "health_check_path", null)
      http2_enabled               = lookup(site_config.value, "http2_enabled", false)
      # ip_restriction              = concat(local.subnets, local.ip_address, local.service_tags)
      scm_use_main_ip_restriction = var.scm_ips_allowed != [] || var.scm_subnet_ids_allowed != null ? false : true
      local_mysql_enabled         = lookup(site_config.value, "local_mysql_enabled", null)
      managed_pipeline_mode       = lookup(site_config.value, "managed_pipeline_mode", "Integrated")
      remote_debugging_enabled    = lookup(site_config.value, "remote_debugging_enabled", null)
      remote_debugging_version    = lookup(site_config.value, "remote_debugging_version", null)
      # scm_type                    = lookup(site_config.value, "scm_type", null)
      websockets_enabled          = lookup(site_config.value, "websockets_enabled", null)

      dynamic "application_stack" {
      for_each = var.application_stack != null && var.application_stack["type"] != "" ? [var.application_stack] : []
        content {
          python_version = application_stack.value["type"] == "PYTHON" ? application_stack.value["version"] : null
          node_version   = application_stack.value["type"] == "NODE" ? application_stack.value["version"] : null
        }
      }

      dynamic "cors" {
        for_each = lookup(site_config.value, "cors", [])
        content {
          allowed_origins     = cors.value.allowed_origins
          support_credentials = lookup(cors.value, "support_credentials", null)
        }
      }
    }
  }

  auth_settings {
    enabled                        = var.enable_auth_settings
    default_provider               = var.default_auth_provider
    allowed_external_redirect_urls = []
    # azurerm_client_config configured
    issuer                         = format("https://sts.windows.net/%s/", data.azurerm_client_config.main.tenant_id)
    unauthenticated_client_action  = var.unauthenticated_client_action
    token_store_enabled            = var.token_store_enabled

    dynamic "active_directory" {
      for_each = var.active_directory_auth_setttings
      content {
        client_id         = lookup(active_directory_auth_setttings.value, "client_id", null)
        client_secret     = lookup(active_directory_auth_setttings.value, "client_secret", null)
        allowed_audiences = concat(formatlist("https://%s", [format("%s.azurewebsites.net", var.app_service_name)]), [])
      }
    }
  }

  dynamic "backup" {
    for_each = var.enable_backup ? [{}] : []
    content {
      name                = coalesce(var.backup_settings.name, "DefaultBackup")
      enabled             = var.backup_settings.enabled
      storage_account_url = format("https://${data.azurerm_storage_account.storeacc.0.name}.blob.core.windows.net/${azurerm_storage_container.storcont.0.name}%s", data.azurerm_storage_account_blob_container_sas.main.0.sas)
      schedule {
        frequency_interval       = var.backup_settings.frequency_interval
        frequency_unit           = var.backup_settings.frequency_unit
        retention_period_days    = var.backup_settings.retention_period_days
        start_time               = var.backup_settings.start_time
      }
    }
  }

  dynamic "connection_string" {
    for_each = var.connection_strings
    content {
      name  = lookup(connection_string.value, "name", null)
      type  = lookup(connection_string.value, "type", null)
      value = lookup(connection_string.value, "value", null)
    }
  }

  identity {
    type         = var.identity_ids != null ? "SystemAssigned, UserAssigned" : "SystemAssigned"
    identity_ids = var.identity_ids
  }

  dynamic "storage_account" {
    for_each = var.storage_mounts
    content {
      name         = lookup(storage_account.value, "name")
      type         = lookup(storage_account.value, "type", "AzureFiles")
      account_name = lookup(storage_account.value, "account_name", null)
      share_name   = lookup(storage_account.value, "share_name", null)
      access_key   = lookup(storage_account.value, "access_key", null)
      mount_path   = lookup(storage_account.value, "mount_path", null)
    }
  }

  lifecycle {
    ignore_changes = [
      tags,
      site_config,
      backup,
      auth_settings,
      storage_account,
      identity,
      connection_string,
    ]
  }
}

#---------------------------------------------------------
# Custom domain and Certificate config
#----------------------------------------------------------
resource "azurerm_app_service_certificate" "main" {
  for_each            = var.custom_domains != null ? { for k, v in var.custom_domains : k => v if v != null } : {}
  name                = each.key
  resource_group_name = var.resource_group_name
  location            = var.location
  pfx_blob            = contains(keys(each.value), "certificate_file") ? filebase64(each.value.certificate_file) : null
  password            = contains(keys(each.value), "certificate_file") ? each.value.certificate_password : null
  key_vault_secret_id = contains(keys(each.value), "certificate_keyvault_certificate_id") ? each.value.certificate_keyvault_certificate_id : null
}

resource "azurerm_app_service_custom_hostname_binding" "cust-host-bind" {
  for_each            = var.custom_domains != null ? var.custom_domains : {}
  hostname            = each.key
  app_service_name    = azurerm_linux_web_app.main.name
  resource_group_name = var.resource_group_name
  ssl_state           = lookup(azurerm_app_service_certificate.main, each.key, false) != false ? "SniEnabled" : null
  thumbprint          = lookup(azurerm_app_service_certificate.main, each.key, false) != false ? azurerm_app_service_certificate.main[each.key].thumbprint : null
}


#---------------------------------------------------------
# Application Insights resoruces - 
#----------------------------------------------------------

resource "azurerm_application_insights" "main" {
  count               = var.application_insights_enabled && var.application_insights_id == null ? 1 : 0
  name                = lower(format("appinsights-%s", var.app_insights_name))
  location            = var.location
  resource_group_name = var.resource_group_name
  application_type    = var.application_insights_type
  retention_in_days   = var.retention_in_days
  disable_ip_masking  = var.disable_ip_masking
  tags                = merge({ "ResourceName" = "${var.app_insights_name}" }, var.tags, )
}

#-------------------------------------------------------------
# App Service Virtual Network Association 
#-------------------------------------------------------------

resource "azurerm_app_service_virtual_network_swift_connection" "main" {
  count          = var.enable_vnet_integration == true ? 1 : 0
  app_service_id = azurerm_linux_web_app.main.id
  subnet_id      = var.subnet_id
}