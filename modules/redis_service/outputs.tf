output "redis_cache_name" {
  description = "The name of the Redis Cache"
  value       = azurerm_redis_cache.redis_cache.name
}

output "redis_cache_hostname" {
  description = "The hostname of the Redis Cache"
  value       = azurerm_redis_cache.redis_cache.hostname
}

output "redis_cache_port" {
  description = "The port of the Redis Cache"
  value       = azurerm_redis_cache.redis_cache.port
}
