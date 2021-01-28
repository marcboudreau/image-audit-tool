################################################################################
#
# Amazon Web Services
#   This project is used to launch a Spot Instance to test an AMI.
#
# main.tf
#   This file defines the resources for the project.
#
################################################################################

terraform {
  backend "local" {
  }
}

provider "aws" {
  region = substr(var.instance_location, 0, length(var.instance_location) - 1)
}

locals {
    default_instance_type = "t2.small"
}

data "aws_vpc" "default" {
    default = true
}

data "aws_subnet_ids" "test" {
    vpc_id = coalesce(var.vpc_identifier, data.aws_vpc.default.id)

    filter {
        name = "availability-zone"
        values = [var.instance_location]
    }
}

resource "aws_key_pair" "test" {
    key_name_prefix = "image-audit-tool-"
    public_key      = var.ssh_public_key
}

resource "aws_security_group" "test" {
    name_prefix = "image-audit-tool-"
    vpc_id      = coalesce(var.vpc_identifier, data.aws_vpc.default.id)

    ingress {
        cidr_blocks = ["0.0.0.0/0"]
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
    }
}

resource "aws_spot_instance_request" "test" {
    wait_for_fulfillment = true
    spot_type            = "one-time"

    ami                         = var.image_id
    associate_public_ip_address = true
    subnet_id                   = tolist(data.aws_subnet_ids.test.ids)[0]
    instance_type               = coalesce(var.instance_type, local.default_instance_type)
    key_name                    = aws_key_pair.test.key_name
    security_groups             = [aws_security_group.test.id]

    tags = {
        Name = "image-audit-${var.image_id}"
        Source = "image-audit-tool"
    }
}
