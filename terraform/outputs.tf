output "ssh_username" {
    description = "The username ultimately specified for SSH connections."
    value       = var.ssh_username
}

output "instance_ip" {
    description = "The IP address of the launched Instance."
    value       = coalesce(module.gcp[0].instance_ip)
}
