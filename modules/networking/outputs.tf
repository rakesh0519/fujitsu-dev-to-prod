output "virtual_network_name" {
  description = "The name of the virtual network"
  value       = azurerm_virtual_network.vnet.name
}

output "virtual_network_id" {
  description = "The id of the virtual network"
  value       = azurerm_virtual_network.vnet.id
}

output "virtual_network_address_space" {
  description = "List of address spaces that are used by the virtual network."
  value       = azurerm_virtual_network.vnet.address_space
}

output "gateway_subnet" {
   description = "ID of the gateway subnet"
   value       = azurerm_subnet.snet["gateway_subnet"].name
}

output "db_subnet_id" {
  description = "ID of the database subnet"
  value       = azurerm_subnet.snet["db_subnet"].id
}

output "frontend_subnet_id" {
  description = "ID of the database subnet"
  value       = azurerm_subnet.snet["frontend_subnet"].id
}

output "backend_subnet_id" {
  description = "ID of the database subnet"
  value       = azurerm_subnet.snet["backend_subnet"].id
}

output "pvt_subnet" {
  value = {
    name             = azurerm_subnet.snet["pvt_subnet"].name
    address_prefix   = azurerm_subnet.snet["pvt_subnet"].address_prefixes
    service_endpoints = azurerm_subnet.snet["pvt_subnet"].service_endpoints
  }
}

output "network_security_group_ids" {
  description = "List of Network security groups and ids"
  value       = [for n in azurerm_network_security_group.nsg : n.id]
}