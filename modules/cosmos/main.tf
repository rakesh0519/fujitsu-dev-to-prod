locals {
  default_failover_locations = [
    {}
  ]
}

data "azurerm_log_analytics_workspace" "logws" {
  name                = var.log_analytics_workspace_name
  resource_group_name = var.resource_group_name
}

data "azurerm_storage_account" "storeacc" {
  name                = var.storage_account_name
  resource_group_name = var.resource_group_name
}

#-------------------------------------------------------------
# CosmosDB (formally DocumentDB) Account 
#-------------------------------------------------------------

resource "random_integer" "intg" {
  min = 500
  max = 50000
  keepers = {
    name = var.resource_group_name
  }
}

resource "azurerm_cosmosdb_account" "main" {
  for_each            = var.cosmosdb_account
  name                = format("%s-%s", each.key, random_integer.intg.result)
  resource_group_name = var.resource_group_name
  location            = var.location
  offer_type          = each.value["offer_type"]
  kind                = each.value["kind"]
  ip_range_filter     = var.allowed_ip_range_cidrs
  analytical_storage_enabled            = each.value["analytical_storage_enabled"]
  public_network_access_enabled         = each.value["public_network_access_enabled"]
  is_virtual_network_filter_enabled     = each.value["is_virtual_network_filter_enabled"]
  key_vault_key_id                      = each.value["key_vault_key_id"]
  access_key_metadata_writes_enabled    = each.value["access_key_metadata_writes_enabled"]
  mongo_server_version                  = each.value["mongo_server_version"]
  network_acl_bypass_for_azure_services = each.value["network_acl_bypass_for_azure_services"]
  network_acl_bypass_ids                = each.value["network_acl_bypass_ids"]
  tags                                  = merge({ "Name" = format("%s-%s", each.key, random_integer.intg.result) }, var.tags, )

  consistency_policy {
    consistency_level       = lookup(var.consistency_policy, "consistency_level", "BoundedStaleness")
    max_interval_in_seconds = lookup(var.consistency_policy, "consistency_level") == "BoundedStaleness" ? lookup(var.consistency_policy, "max_interval_in_seconds", 5) : null
    max_staleness_prefix    = lookup(var.consistency_policy, "consistency_level") == "BoundedStaleness" ? lookup(var.consistency_policy, "max_staleness_prefix", 100) : null
  }

  dynamic "geo_location" {
    for_each = var.failover_locations == null ? local.default_failover_locations : var.failover_locations
    content {
      location          = geo_location.value.location
      failover_priority = lookup(geo_location.value, "failover_priority", 0)
      zone_redundant    = lookup(geo_location.value, "zone_redundant", false)
    }
  }

  dynamic "capabilities" {
    for_each = toset(var.capabilities)
    content {
      name = capabilities.key
    }
  }

  dynamic "virtual_network_rule" {
    for_each = var.virtual_network_rules != null ? toset(var.virtual_network_rules) : []
    content {
      id                                   = virtual_network_rule.value.id
      ignore_missing_vnet_service_endpoint = virtual_network_rule.value.ignore_missing_vnet_service_endpoint
    }
  }

  dynamic "backup" {
    for_each = var.backup != null ? [var.backup] : []
    content {
      type                = lookup(var.backup, "type", null)
      interval_in_minutes = lookup(var.backup, "interval_in_minutes", null)
      retention_in_hours  = lookup(var.backup, "retention_in_hours", null)
    }
  }

  dynamic "cors_rule" {
    for_each = var.cors_rules != null ? [var.cors_rules] : []
    content {
      allowed_headers    = var.cors_rules.allowed_headers
      allowed_methods    = var.cors_rules.allowed_methods
      allowed_origins    = var.cors_rules.allowed_origins
      exposed_headers    = var.cors_rules.exposed_headers
      max_age_in_seconds = var.cors_rules.max_age_in_seconds
    }
  }

  dynamic "identity" {
    for_each = var.managed_identity == true ? [1] : [0]
    content {
      type = "SystemAssigned"
    }
  }
  
  lifecycle {
    ignore_changes = [
      # List the attributes you want to ignore changes for
      ip_range_filter,
      analytical_storage_enabled,
      public_network_access_enabled,
      is_virtual_network_filter_enabled,
      key_vault_key_id,
      access_key_metadata_writes_enabled,
      network_acl_bypass_for_azure_services,
      network_acl_bypass_ids,
      tags,
      consistency_policy,
      geo_location,
      capabilities,
      virtual_network_rule,
      backup,
      cors_rule,
    ]
  }
}

#-------------------------------------------------------------
#  CosmosDB azure defender configuration 
#-------------------------------------------------------------
resource "azurerm_advanced_threat_protection" "threat_protection" {
  count              = var.enable_advanced_threat_protection ? 1 : 0
  target_resource_id = element([for n in azurerm_cosmosdb_account.main : n.id], 0)
  enabled            = var.enable_advanced_threat_protection
}

#---------------------------------------------------------
#  CosmosDB SQL Database
#---------------------------------------------------------
resource "azurerm_cosmosdb_sql_database" "main" {
  # count               = var.create_cosmosdb_sql_database || var.create_cosmosdb_sql_container ? 1 : 0
  name                = var.cosmosdb_sql_database_name == null ? format("%s-sql-database", element([for n in azurerm_cosmosdb_account.main : n.name], 0)) : var.cosmosdb_sql_database_name
  resource_group_name = var.resource_group_name
  account_name        = element([for n in azurerm_cosmosdb_account.main : n.name], 0)
  # throughput          = var.cosmosdb_sqldb_autoscale_settings == null ? var.cosmosdb_sqldb_throughput : null

  dynamic "autoscale_settings" {
    for_each = var.cosmosdb_db_autoscale_settings != null ? [var.cosmosdb_db_autoscale_settings] : []
    content {
      max_throughput = var.cosmosdb_sqldb_throughput == null ? var.cosmosdb_table_autoscale_settings.max_throughput : null
    }
  }
  
  lifecycle {
    ignore_changes = [
      # List the attributes you want to ignore changes for
      name,
      throughput,
      autoscale_settings,
    ]
  }
}

#---------------------------------------------------------
#  CosmosDB SQL Container
#---------------------------------------------------------
resource "azurerm_cosmosdb_sql_container" "main" {
  # count                  = var.create_cosmosdb_sql_container ? 1 : 0
  name                   = var.cosmosdb_sql_container_name == null ? format("%s-sql-container", element([for n in azurerm_cosmosdb_account.main : n.name], 0)) : var.cosmosdb_sql_container_name
  resource_group_name    = var.resource_group_name
  account_name           = element([for n in azurerm_cosmosdb_account.main : n.name], 0)
  database_name          = azurerm_cosmosdb_sql_database.main.name
  partition_key_paths    = var.partition_key_paths
  partition_key_version  = var.partition_key_version
  throughput             = var.sql_container_autoscale_settings == null ? var.sql_container_throughput : null
  default_ttl            = var.default_ttl
  analytical_storage_ttl = var.analytical_storage_ttl

  dynamic "unique_key" {
    for_each = var.unique_key != null ? [var.unique_key] : []
    content {
      paths = var.unique_key.paths
    }
  }

  dynamic "autoscale_settings" {
    for_each = var.sql_container_autoscale_settings != null ? [var.sql_container_autoscale_settings] : []
    content {
      max_throughput = var.sql_container_throughput == null ? var.sql_container_autoscale_settings.max_throughput : null
    }
  }

  dynamic "indexing_policy" {
    for_each = var.indexing_policy != null ? [var.indexing_policy] : []
    content {
      indexing_mode = var.indexing_policy.indexing_mode

      dynamic "included_path" {
        for_each = lookup(var.indexing_policy, "included_path") != null ? [lookup(var.indexing_policy, "included_path")] : []
        content {
          path = var.indexing_policy.included_path.path
        }
      }

      dynamic "excluded_path" {
        for_each = lookup(var.indexing_policy, "excluded_path") != null ? [lookup(var.indexing_policy, "excluded_path")] : []
        content {
          path = var.indexing_policy.excluded_path.path
        }
      }

      dynamic "composite_index" {
        for_each = lookup(var.indexing_policy, "composite_index") != null ? [lookup(var.indexing_policy, "composite_index")] : []
        content {
          index {
            path  = var.indexing_policy.composite_index.index.path
            order = var.indexing_policy.composite_index.index.order
          }
        }
      }

      dynamic "spatial_index" {
        for_each = lookup(var.indexing_policy, "spatial_index") != null ? [lookup(var.indexing_policy, "spatial_index")] : []
        content {
          path = var.indexing_policy.spatial_index.path
        }
      }
    }
  }

  dynamic "conflict_resolution_policy" {
    for_each = var.conflict_resolution_policy != null ? [var.conflict_resolution_policy] : []
    content {
      mode                          = var.conflict_resolution_policy.mode
      conflict_resolution_path      = var.conflict_resolution_policy.conflict_resolution_path
      conflict_resolution_procedure = var.conflict_resolution_policy.conflict_resolution_procedure
    }
  }
  
  lifecycle {
    ignore_changes = [
      # List the attributes you want to ignore changes for
      name,
      throughput,
      autoscale_settings,
      partition_key_paths,
      partition_key_version,
      default_ttl,
      analytical_storage_ttl,
      unique_key,
    ]
  }
}

resource "azurerm_cosmosdb_sql_dedicated_gateway" "cosmosdb_dedicated_gateway" {
  cosmosdb_account_id = element([for n in azurerm_cosmosdb_account.main : n.id], 0)
  instance_size       = var.dedicated_instance_size
  instance_count      = var.dedicated_instance_count
}

#---------------------------------------------------------
# Private Link for CosmosDB Server
#---------------------------------------------------------
data "azurerm_virtual_network" "vnet" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = var.virtual_network_name
  resource_group_name = var.resource_group_name
}

data "azurerm_subnet" "snet" {
  count                = var.enable_private_endpoint ? 1 : 0
  name                 = "pvt_subnet"
  virtual_network_name = data.azurerm_virtual_network.vnet.0.name
  resource_group_name  = var.resource_group_name
}

resource "azurerm_private_endpoint" "pep1" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = format("%s-private-endpoint", element([for n in azurerm_cosmosdb_account.main : n.name], 0))
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = data.azurerm_subnet.snet.0.id
  tags                = merge({ "Name" = format("%s-private-endpoint", element([for n in azurerm_cosmosdb_account.main : n.name], 0)) }, var.tags, )

  private_service_connection {
    name                           = "privatelink"
    is_manual_connection           = false
    private_connection_resource_id = element([for n in azurerm_cosmosdb_account.main : n.id], 0)
    subresource_names              = ["Sql"]
  }
  
  lifecycle {
    ignore_changes = [
      # List the attributes you want to ignore changes for
      subnet_id,
      private_service_connection,
    ]
  }
}

data "azurerm_private_endpoint_connection" "private-ip1" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = azurerm_private_endpoint.pep1.0.name
  resource_group_name = var.resource_group_name
  depends_on          = [azurerm_cosmosdb_account.main]
}

resource "azurerm_private_dns_zone" "dnszone1" {
  count               = var.existing_private_dns_zone == null && var.enable_private_endpoint ? 1 : 0
  name                = "privatelink.documents.azure.com"
  resource_group_name = var.resource_group_name
  tags                = merge({ "Name" = format("%s", "Private-DNS-Zone") }, var.tags, )
}

resource "azurerm_private_dns_zone_virtual_network_link" "vent-link1" {
  count                 = var.existing_private_dns_zone == null && var.enable_private_endpoint ? 1 : 0
  name                  = "vnet-private-zone-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.dnszone1.0.name
  virtual_network_id    = data.azurerm_virtual_network.vnet.0.id
  tags                  = merge({ "Name" = format("%s", "vnet-private-zone-link") }, var.tags, )
  
  lifecycle {
    ignore_changes = [
      # List the attributes you want to ignore changes for
      virtual_network_id,
    ]
  }
}

resource "azurerm_private_dns_a_record" "arecord1" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = element([for n in azurerm_cosmosdb_account.main : n.name], 0)
  zone_name           = var.existing_private_dns_zone == null ? azurerm_private_dns_zone.dnszone1.0.name : var.existing_private_dns_zone
  resource_group_name = var.resource_group_name
  ttl                 = 300
  records             = [data.azurerm_private_endpoint_connection.private-ip1.0.private_service_connection.0.private_ip_address]
  lifecycle {
    ignore_changes = [records]
  }
}

#------------------------------------------------------------------
# azurerm monitoring diagnostics
#------------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "extaudit" {
  name                       = lower("extaudit-${element([for n in azurerm_cosmosdb_account.main : n.name], 0)}-diag")
  target_resource_id         = element([for n in azurerm_cosmosdb_account.main : n.id], 0)
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.logws.id
  storage_account_id         = data.azurerm_storage_account.storeacc.id

  dynamic "enabled_log" {
    for_each = var.extaudit_diag_logs
    content {
      category = enabled_log.value
    }
  }

  metric {
    category = "Requests"
    enabled = true
  }

  lifecycle {
    ignore_changes = [enabled_log, metric]
  }
}