variable "resource_group_name" {
  description = "resource group"
}

variable "location" {
  description = "location/region"
}

variable "log_analytics_workspace_name" {
  type = string
  description = "Name of the log analytics workspace"
}

variable "sku" {
  type = string
  description = "Log analytics workspace SKU"
}

variable "retention_in_days" {
  type = number
  description = "Retention days"
}