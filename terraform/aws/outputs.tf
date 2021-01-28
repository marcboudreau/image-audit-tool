################################################################################
#
# Amazon Web Services
#   This project is used to launch an AWS EC2 Instance to test an AMI.
#
# outputs.tf
#   This file defines the output variables for the project.
#
################################################################################

output "instance_ip" {
    description = "The public IP address of the Spot Instance launched to test the AMI."
    value       = aws_spot_instance_request.test.public_ip
}

output "ssh_username" {
    description = "The username ultimately specified for SSH connections."
    value       = var.ssh_username
}
