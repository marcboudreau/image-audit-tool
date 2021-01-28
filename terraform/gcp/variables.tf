################################################################################
#
# Google Cloud Platform
#   This project is used to launch a preemptible GCE Instance to test a GCE
#   Image.
#
# variables.tf
#   This file defines the variables for the project.
#
################################################################################

variable "image_id" {
    description = "The specific name of a GCE Image to use as the boot disk image for the launched GCE Instance."
    type        = string
}

variable "machine_type" {
    description = "The machine type used by the GCE Instance launched to test the GCE Image. If set to empty, the local value default_machine_type will be used instead."
    type        = string
    default     = ""
}

variable "zone" {
    description = "The availability zone where the GCE Instance is launched."
    type = string
}

variable "vpc_identifier" {
    description = "The name of the GCP network in which the GCE Instance is launched."
    type        = string
    default     = "default"
}

variable "ssh_username" {
    description = "The username to use when connecting with SSH to the launched GCE Instance."
    type        = string
    default     = "ubuntu"
}

variable "ssh_public_key" {
    description = "The public key to install on the launched GCE Instance to allow SSH connections."
    type        = string
}

variable "project" {
    description = "The GCP project to use for launching the GCE Instance."
    type        = string

    validation {
        condition     = length(var.project) > 0
        error_message = "A valid Google Cloud Platform project identifier must be provided."
    }
}

variable "preemptible_instance" {
  description = "Indicates whether a preemptible GCE Instance is used."
  type        = bool
  default     = true
}

variable "enable_secure_boot" {
    description = "Indicates whether the secure boot option is enabled on the launched GCE Instance."
    type        = bool
    default     = true
}

variable "enable_vtpm" {
    description = "Indicates whether the vtpm option is enabled on the launched GCE Instance."
    type        = bool
    default     = true
}

variable "enable_integrity_monitoring" {
    description = "Indicates whether the integrity monitoring option is enabled on the launched GCE Instance."
    type        = bool
    default     = true
}
