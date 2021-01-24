################################################################################
#
# CIS Test Harness
#   This Terraform project is used to launch virtual instances in various cloud
#   providers to test machine images produced in those cloud providers.
#
# variables.tf 
#   This file defines the input variables for this Terraform project.
#
################################################################################

variable "image_cloud" {
    description = "The canonical name of a supported cloud vendor."
    type        = string

    validation {
        condition     = contains(["gcp"], var.image_cloud)
        error_message = "The image_cloud value must be one of the following elements: gcp."
    }
}

variable "image_identifier" {
    description = "An identifier used by the corresponding cloud provider to uniquely identify the Image being tested."
    type        = string
}

variable "machine_type" {
    description = "The type of Instance to launch to test an Image. This value is cloud provider specific, but each module will use a reasonable default if this value is empty."
    type        = string
    default     = ""
}

variable "instance_location" {
    description = "A cloud provider location identifier used to specify the specific location where the Instance will be launched. In most cases, this an availability zone."
    type        = string
}

variable "vpc_identifier" {
    description = "An identifier used by the corresponding cloud provider to uniquely identify the VPC network where the Instance will be launched."
    type        = string
}

variable "ssh_username" {
    description = "The username used to establish the SSH connection to the launched Instance."
    type        = string
    default     = "ubuntu"
}

variable "ssh_public_key" {
    description = "The public key to install on the launched Instance to allow SSH connections."
    type        = string
}

variable "gcp_project" {
    description = "The project identifier for the Google Cloud Platform module. This variable is ignored when using another cloud provider."
    type        = string
    default     = ""
}

variable "gcp_preemptible_instance" {
    description = "A flag indicating if the launched Instance in Google Cloud Platform is preemptible. This variable is ignored when using another cloud provider."
    type        = bool
    default     = true
}

variable "gcp_enable_secure_boot" {
    description = "A flag indicating if the secure boot option is enabled on the launched Instance in Google Cloud Platform. This variable is ignored when using another cloud provider."
    type        = bool
    default     = true
}

variable "gcp_enable_vtpm" {
    description = "A flag indicating if the vtpm option is enabled on the launched Instance in Google Cloud Platform. This variable is ignored when using another cloud provider."
    type        = bool
    default     = true
}

variable "gcp_enable_integrity_monitoring" {
    description = "A flag indicating if the integrity monitoring option is enabled on the launched Instance in Google Cloud Platform. This variable is ignored when using another cloud provider."
    type        = bool
    default     = true
}