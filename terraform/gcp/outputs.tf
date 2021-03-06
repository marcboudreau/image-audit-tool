################################################################################
#
# Google Cloud Platform
#   This project is used to launch a preemptible GCE Instance to test a GCE
#   Image.
#
# outputs.tf
#   This file defines the output variables for the project.
#
################################################################################

output "instance_ip" {
    description = "The ephmeral IP address assigned to the launched GCE Instance."
    value       = google_compute_instance.test.network_interface[0].access_config[0].nat_ip
}

output "ssh_username" {
    description = "The username ultimately specified for SSH connections."
    value       = var.ssh_username
}
