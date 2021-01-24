################################################################################
#
# Google Cloud Platform module
#   This module is used to launch a GCE Instance to test a GCE
#   Image.
#
# main.tf
#   This file defines the resources for the module.
#
################################################################################

resource "google_compute_instance" "test" {
    boot_disk {
      initialize_params {
          image = var.image_name
      }
    }

    machine_type = coalesce(var.machine_type, local.default_machine_type)
    name         = "cis-test-${var.image_name}"
    zone         = var.zone

    network_interface {
        network = coalesce(var.network_name, local.default_network_name)

        access_config {}
    }

    allow_stopping_for_update = false
    metadata = {
        ssh-keys = "${var.ssh_username}:${var.ssh_public_key}"
    }

    project = var.project

    scheduling {
      preemptible = true
      automatic_restart = false
    }

    service_account {
      scopes = ["cloud-platform"]
    }

    shielded_instance_config {
      enable_secure_boot          = var.enable_secure_boot
      enable_vtpm                 = var.enable_vtpm
      enable_integrity_monitoring = var.enable_integrity_monitoring
    }
}