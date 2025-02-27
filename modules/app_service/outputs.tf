output "app_service_plan_id" {
  description = "The resource ID of the App Service Plan component"
  value       = azurerm_service_plan.main.id
}

output "app_service_id" {
  description = "The resource ID of the App Service component"
  value       = azurerm_linux_web_app.main.id
}

output "default_hostname" {
  description = "The default hostname of the App Service"
  value       = azurerm_linux_web_app.main.default_hostname
}

output "outbound_ip_addresses" {
  description = "A comma separated list of outbound IP addresses"
  value       = azurerm_linux_web_app.main.outbound_ip_addresses
}

output "outbound_ip_address_list" {
  description = "A list of outbound IP addresses"
  value       = azurerm_linux_web_app.main.outbound_ip_address_list
}

output "possible_outbound_ip_addresses" {
  description = "A comma separated list of outbound IP addresses - not all of which are necessarily in use. Superset of `outbound_ip_addresses`."
  value       = azurerm_linux_web_app.main.possible_outbound_ip_addresses
}

output "possible_outbound_ip_address_list" {
  description = "A list of outbound IP addresses - not all of which are necessarily in use. Superset of outbound_ip_address_list."
  value       = azurerm_linux_web_app.main.possible_outbound_ip_address_list
}

output "identity" {
  description = "An identity block, which contains the Managed Service Identity information for this App Service."
  value       = azurerm_linux_web_app.main.identity
}

output "application_insights_id" {
  description = "The ID of the Application Insights component"
  value       = var.application_insights_enabled ? azurerm_application_insights.main.*.id : null
}

output "application_insights_app_id" {
  description = "The App ID associated with this Application Insights component"
  value       = var.application_insights_enabled ? azurerm_application_insights.main.*.app_id : null
}

output "application_insights_instrumentation_key" {
  description = "The Instrumentation Key for this Application Insights component"
  value       = var.application_insights_enabled ? azurerm_application_insights.main.*.instrumentation_key : null
  sensitive   = true
}

output "application_insights_connection_string" {
  description = "The Connection String for this Application Insights component"
  value       = var.application_insights_enabled ? azurerm_application_insights.main.*.connection_string : null
  sensitive   = true
}

output "sas_url_query_string" {
  description = "The computed Blob Container Shared Access Signature (SAS)"
  value       = var.enable_backup ? format("https://${data.azurerm_storage_account.storeacc.0.name}.blob.core.windows.net/${azurerm_storage_container.storcont.0.name}%s", data.azurerm_storage_account_blob_container_sas.main.0.sas) : null
  sensitive   = true
}

output "app_service_virtual_network_swift_connection_id" {
  description = "The ID of the App Service Virtual Network integration"
  value       = var.enable_vnet_integration ? azurerm_app_service_virtual_network_swift_connection.main.*.id : null
}