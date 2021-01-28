################################################################################
#
# Amazon Web Services
#   This project is used to launch an AWS EC2 Instance to test an AMI.
#
# variables.tf
#   This file defines the variables for the project.
#
################################################################################

variable "ssh_public_key" {
    description = "The public key to install on the launched GCE Instance to allow SSH connections."
    type        = string
}

variable "ssh_username" {
    description = "The username ultimately used for establishing SSH connection."
    type        = string
    default     = "ubuntu"
}

variable "image_id" {
    description = "The unique identifier for the AMI being tested."
    type        = string
}

variable "instance_type" {
    description = "The instance type used by the EC2 Instance launched to test the AMI. If set to empty, a default instance type will be used instead."
    type        = string
    default     = ""
}

variable "instance_location" {
    description = "The availability zone where the EC2 Instance is launched to test the AMI."
    type        = string
}

variable "vpc_identifier" {
    description = "The unique identifier for the VPC to use for the EC2 Instance."
    type        = string
    default     = ""
}
