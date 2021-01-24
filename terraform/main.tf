################################################################################
#
# CIS Test Harness
#   This Terraform project is used to launch virtual instances in various cloud
#   providers to test machine images produced in those cloud providers.
#
# main.tf
#   This file defines the modules available to this project.
#
################################################################################

terraform {
  backend "local" {
  }
}

provider "google" {
    project = var.gcp_project
}

module "gcp" {
    source = "./gcp"
    count  = var.image_cloud == "gcp" ? 1 : 0

    image_name   = var.image_identifier
    machine_type = var.machine_type
    zone         = var.instance_location
    network_name = var.vpc_identifier
    project      = var.gcp_project   

    ssh_username   = var.ssh_username
    ssh_public_key = var.ssh_public_key

    preemptible_instance        = var.gcp_preemptible_instance
    enable_secure_boot          = var.gcp_enable_secure_boot
    enable_vtpm                 = var.gcp_enable_vtpm
    enable_integrity_monitoring = var.gcp_enable_integrity_monitoring
}
