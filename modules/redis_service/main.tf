resource "azurerm_redis_cache" "redis_cache" {
  name                = var.redis_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku_name            = var.sku_name
  capacity            = var.capacity
  family              = var.family

# redis_configuration {
#   enable_non_ssl_port = var.enable_non_ssl_port
# }

# Note: If enabling the non-SSL port is required, this can also be configured manually via the Azure Portal.
# This is a one-time activity and does not require frequent updates unless the requirement changes.

  tags = var.tags
}
