#!/bin/bash
set -${DEBUG:+x}o pipefail

failures=0
skips=0
passes=0
counting_level2=false

function report {
    local result=$?
    local control_number=$1
    local control_title=$2
    local level=${3:-"Level 1"}

    if [ $result -eq 0 ] ; then
        echo "$control_number $control_title ($level): PASSED"
        passes=$(($passes+1))
    elif [[ $level == "Level 2" ]] && [[ $counting_level2 == false ]] || grep -q "^$control_number$" /tmp/exceptions ; then
        echo "$control_number $control_title ($level): SKIPPED"
        skips=$(($skips+1))
    else
        echo "$control_number $control_title ($level): FAILED"
        failures=$(($failures+1))
    fi
}

if (( $# == 0 )) ; then
    echo "Warning: No test script specified."
else
    if [ ! -f $1 ]; then
        echo "Error: The specified test script $1 is not readable" >&2
        stat $1 >&2
        exit 1
    else
        if [[ ${2:-} == "level=2" ]] ; then
            counting_level2=true
        fi
        . $1
    fi
fi

total_tests=$(($passes+$failures+$skips))
echo "Passing controls $passes, rate $(($passes*100/$total_tests))%"
echo "Failing controls $failures, rate $(($failures*100/$total_tests))%"
echo "Skipped controls $skips, rate $(($skips*100/$total_tests))%"
[ $failures -eq 0 ]
