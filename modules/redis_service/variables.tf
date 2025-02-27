variable "redis_name" {
  description = "Name of the Redis Cache"
  type        = string
}

variable "location" {
  description = "Location of the Redis Cache"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
}

variable "sku_name" {
  description = "SKU name for Redis Cache"
  type        = string
}

variable "capacity" {
  description = "Capacity of the Redis Cache"
  type        = number
}

variable "family" {
  description = "Redis family (e.g., C for Redis version 6.x)"
  type        = string
  default     = "C"
}

variable "enable_non_ssl_port" {
  description = "Whether to enable non-SSL port"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to the Redis Cache"
  type        = map(string)
}
