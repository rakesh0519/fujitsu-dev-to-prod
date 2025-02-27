output "log_analytics_workspace_name" {
  description = "Log Analytics Workspace Name"
  value = azurerm_log_analytics_workspace.logws.name
}