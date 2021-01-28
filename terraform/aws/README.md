# image-audit-tool - aws

This page describes using this tool with Amazon Web Services as the target cloud provider.

## Usage

### Command Line Arguments

When targetting Amazon Web Services, the `<cloud>` argument must be `aws`.

In Amazon Web Services, the image identifier is referred as the AMI id, a unique identifier starting with `ami-` and followed by hexadecimal digits.

### Environment Variables

For Amazon Web Services, the **CLOUD_LOCATION** environment variable must be set to an availability zone where the EC2 Spot Instance will be launched.

Amazon Web Services provide a default VPC which can be used by omitting the **VPC_IDENTIFIER** environment variable from the Docker container.  However, if a different VPC must be used, specify the VPC id as the value of the **VPC_IDENTIFIER** environment variable.

Access credentials for Amazon Web Services are provided through the **AWS_ACCESS_KEY_ID** and **AWS_SECRET_ACCESS_KEY** environment variables. If using credentials otained from the AWS Security Token Service, a third environment variable named **AWS_SESSION_TOKEN** must also be set.

`-e AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id) -e AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key)`

### Volume Mounts

No volume mounts are necessary when using Amazon Web Services.
