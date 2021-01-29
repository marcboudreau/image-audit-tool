#!/bin/bash
set -e

failures=0
exceptions_file_present=0

if [ -f /tmp/exceptions ]; then
    exceptions_file_present=1
fi

function report {
    local control_number=$1

    if [ $exceptions_file_present -ne 0 ] && grep -q "^$control_number$" /tmp/exceptions ; then
        echo "$control_number SKIPPED"
    else
        echo "$control_number FAILED"
        failures=$(expr $failures + 1)
    fi
}

if [ $# -eq 0 ]; then
    echo "Warning: No test script specified."
else
    if [ ! -f $1 ]; then
        echo "Error: The specified test script $1 is not readable" >&2
        stat $1 >&2
        exit 1
    else
        . $1
    fi
fi

# Check if there were any failures
[ $failures -eq 0 ]
