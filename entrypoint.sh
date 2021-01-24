#!/bin/ash
set -eu${DEBUG+x}o pipefail

#
# print_usage:
#   Prints the command line usage for this Docker image to the standard output
#   stream.
#
function print_usage {
    echo "Usage:"
    echo "  <cloud> <image_identifier>"
    echo ""
    echo "Where:"
    echo "  <cloud>             The canonical name of the cloud provider where the"
    echo "                      candidate image exists."
    echo "  <image_identifier>  The unique identifier for the candidate image to test."
    echo ""
    echo "Environment Variables:"
    echo "  CLOUD_LOCATION      The cloud provider location (zone or region) where the"
    echo "                      test instance is launched."
    echo "  VPC_IDENTIFIER      Optional. An identifier for the VPC network to use for the"
    echo "                      launched Instance. Some cloud providers have a default VPC"
    echo "                      that can be used when this variable is not set."
    echo ""
    echo "Terraform Variables:"
    echo "  The required Terraform variables are automatically set using the above-"
    echo "  described options and environment variables.  Any optional Terraform variable"
    echo "  can be specified a value by setting an environment variable whose name matches"
    echo "  the Terraform variable name with the prefixed 'TF_VAR_' (case matters) added."
    echo ""
    echo "  For example:"
    echo "    To set gcp_project, set TF_VAR_gcp_project to the desired value."
    echo "" 
}

#
# ssh_ready:
#   This function repeatedly tries to test whether the SSH port is ready for a
#   given IP address.  It will poll port 22 up to 100 times, waiting 1 second
#   in between each attempt.  If after 100 attempts, the port is still not open,
#   the function returns a non-zero value.
#
function ssh_ready {
    local ip_addr=$1
    local ssh_port=${2:-"22"}

    tries=0
    while ! nc -z $ip_addr $ssh_port > /dev/null 2>&1 ; do
        tries=$(($tries + 1))
        if [ $tries -gt 100 ]; then
            echo "Maximum number of attempts to reach port $ssh_port on $ip_addr"
            return 1
        fi

        sleep 1
    done

    return 0
}

# Determine the specified cloud provider from the first command line argument.
cloud=${1:-"help"}

# Detect if the user simply wanted usage information.
if [ "$cloud" = "help" ]; then
    print_usage
    exit 0
fi

# Validate the value of the cloud variable.
#  It must match one of the supported cloud vendors.  To do so, look if the
#  /terrform directory contains a sub-directory with a name matching the
#  cloud variable value.
if [ ! -d /terraform/$cloud ]; then
    echo "Error: the specified cloud provider $cloud is not supported by this tool."
    exit 1
fi

export TF_VAR_image_cloud=$cloud
export TF_VAR_image_identifier=${2:?"Error: an image identifier must be provided."}
export TF_VAR_instance_location=${CLOUD_LOCATION:?"Error: an appropriate cloud provider location must be provided via the CLOUD_LOCATION environment variable."}
export TF_VAR_vpc_identifier=${VPC_IDENTIFIER-""}

ssh-keygen -q -b 2048 -t rsa -N '' -C '' -f /tmp/id_rsa

export TF_VAR_ssh_public_key=$(cat /tmp/id_rsa.pub)

terraform init -input=false -upgrade

# Because the next few commands won't terminate the container immediately on
# failure, track the exit code in this variable.
exit_code=0
(
    # Run Terraform to launch the test Instance.
    terraform apply -input=false -auto-approve || exit_code=2

    if [ $exit_code -eq 0 ]; then
        # Generate the verify.env file which defines environment variables used by
        # the audit.sh script to ignore justified failures.
        if [ -f /verify/exceptions/exceptions.json ]; then
            jq -r 'keys[]' /verify/exceptions/exceptions.json 2> /dev/null > /tmp/verify.env
        fi

        ip_address=$(terraform output -no-color -json instance_ip | jq -r '.') || exit_code=4
        if [ $exit_code -eq 0 ]; then
            ssh_username=$(terraform output -no-color -json ssh_username | jq -r '.') || exit_code=8

            if [ $exit_code -eq 0 ]; then
                # Wait for instance to be provisioned and SSH to become available
                if ssh_ready $ip_address ${SSH_PORT:-"22"} ; then
                    # Upload audit.sh and /tmp/verify.env
                    scp -q -i /tmp/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /verify/audit.sh "$ssh_username@$ip_address:/tmp/audit.sh"

                    if [ -f /tmp/verify.env ]; then
                        scp -q -i /tmp/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /tmp/verify.env "$ssh_username@$ip_address:/tmp/exceptions"
                    fi

                    # Adjust permissions and ownership of the audit.sh file and run it.
                    ssh -i /tmp/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR "$ssh_username@$ip_address" "sudo chmod 0755 /tmp/audit.sh"
                    ssh -i /tmp/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR "$ssh_username@$ip_address" "sudo chown root:root /tmp/audit.sh"

                    # Run the audit.sh script
                    ssh -i /tmp/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR "$ssh_username@$ip_address" "sudo bash /tmp/audit.sh" || exit_code=16
                fi
            fi
        fi
    fi

    exit $exit_code
) || exit_code=1

terraform destroy -auto-approve || true

if [ $exit_code -ne 0 ]; then
    echo "========================================"
    echo " FAILURE"
    echo "========================================"
fi

exit $exit_code
