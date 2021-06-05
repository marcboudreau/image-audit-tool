#!/bin/ash
set -eu${DEBUG+x}o pipefail


#
# print_usage:
#   Prints the command line usage for this Docker image to the standard output
#   stream.
#
function print_usage {
    echo "Usage:"
    echo "  <cloud> <image_identifier> <ignored_controls>"
    echo ""
    echo "Where:"
    echo "  <cloud>             The canonical name of the cloud provider where the"
    echo "                      candidate image exists."
    echo "  <image_identifier>  The unique identifier for the candidate image to test."
    echo "  <test_script>       The test script to execute for the audit. This must be"
    echo "                      the test script filename."
    echo "  <ignored_controls>  Optional. A comma-separated list of control numbers to"
    echo "                      ignore if they fail."
    echo "                      e.g. 1.1,2.3.4,3.1.1"
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

output_redirect="/dev/null"
debug_export=":"

if [ "${LOGLEVEL:-}" == "VERBOSE" ] || [ "${LOGLEVEL:-}" == "DEBUG" ] ; then
    output_redirect="/dev/stdout"

    if [ "${LOGLEVEL:-}" == "DEBUG" ] ; then
        debug_export="export DEBUG=1"
    fi
fi

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
cd /terraform/$cloud

export TF_VAR_image_id=${2:?"Error: an image identifier must be provided."}

test_script=${3:?"Error: a test script must be specified."}
ignored_controls=${4:-}
generate_exceptions_file=
if [ $ignored_controls ]; then
    echo "$ignored_controls" | sed 's/,/\n/g' > /tmp/exceptions
else
    echo "" > /tmp/exceptions
fi

export TF_VAR_instance_location=${CLOUD_LOCATION:?"Error: an appropriate cloud provider location must be provided via the CLOUD_LOCATION environment variable."}
export TF_VAR_vpc_identifier=${VPC_IDENTIFIER-""}

ssh-keygen -q -b 2048 -t rsa -N '' -C '' -f /tmp/id_rsa

export TF_VAR_ssh_public_key=$(cat /tmp/id_rsa.pub)

terraform init -input=false -upgrade &> $output_redirect

# Because the next few commands won't terminate the container immediately on
# failure, track the exit code in this variable.
exit_code=0
(
    # Run Terraform to launch the test Instance.
    terraform apply -input=false -auto-approve &> $output_redirect || exit 1

    if [ $ignored_controls ]; then
        echo "$ignored_controls" | sed 's/,/\n/g' > /tmp/exceptions
    fi
        
    ip_address=$(terraform output -no-color -json instance_ip | jq -r '.') || exit 1
    ssh_username=$(terraform output -no-color -json ssh_username | jq -r '.') || exit 1

    # Blocks execution until the SSH port is ready on the specified IP address.
    ssh_ready $ip_address ${SSH_PORT:-"22"} || exit 1

    # Upload audit.sh and test script.
    scp -q -i /tmp/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /verify/audit.sh "$ssh_username@$ip_address:/tmp/audit.sh"
    scp -q -i /tmp/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /verify/$test_script "$ssh_username@$ip_address:/tmp/testscript"
    scp -q -i /tmp/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /tmp/exceptions "$ssh_username@$ip_address:/tmp/exceptions"

    # Sleep 5 seconds to give the fresh system the time to stabilize before running the audit.
    sleep 5

    # Establish SSH connection to configure file permissions and execute audit.
    ssh -i /tmp/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR "$ssh_username@$ip_address" "sudo bash -c 'chown root:root /tmp/audit.sh /tmp/testscript /tmp/exceptions; chmod 0500 /tmp/audit.sh; mv /tmp/audit.sh /root/audit.sh; chmod 0400 /tmp/testscript /tmp/exceptions; ${debug_export:-} ; /root/audit.sh /tmp/testscript level=${CIS_LEVEL:-1}'" || exit 1
) || exit_code=1

if [ "${DEBUG+x}" = "x" ]; then
    read -p "Test Instance destruction paused until ENTER is pressed: " answer
fi

terraform destroy -auto-approve &> $output_redirect || true

if [ $exit_code -ne 0 ]; then
    echo "========================================"
    echo " FAILURE"
    echo "========================================"
fi

exit $exit_code
