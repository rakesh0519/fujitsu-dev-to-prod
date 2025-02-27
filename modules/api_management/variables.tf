variable "api_management_name" {
  description = "The name of the API Management instance"
  type        = string
}

variable "location" {
  description = "The location where the API Management instance will be created"
  type        = string
}

variable "resource_group_name" {
  description = "The name of the resource group"
  type        = string
}

variable "publisher_name" {
  description = "The name of the publisher"
  type        = string
}

variable "publisher_email" {
  description = "The email of the publisher"
  type        = string
}

variable "sku_name" {
  description = "The SKU of the API Management instance"
  type        = string
}
