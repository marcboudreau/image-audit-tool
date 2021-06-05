# image-audit-tool - Audit Scripts

This tool is designed to support any audit script that adheres to the interface specified on this page. This is done by having a master script named audit.sh which provides the reporting and handling of ignored controls, which then executes the statements contained in a specified file (test script).

## Test Scripts

The tool currently provides the following test scripts:

* `cis-ubuntu-linux-20.04-lts-benchmarks-1.1.0.sh` - All Server controls from the CIS Ubuntu Linux 20.04 LTS Benchmark version 1.1.0

### Developing Test Scripts

This section describes how the test script is structured for those interested in creating a custom test script.

#### Test Script Structure

The following extract shows the contents of a test script:

```bash
(
    grep -q 'some_value' /etc/some.file
) || report "1.2.3" "Ensure some value"

(
    [ modprobe -n -v blah | grep -E '(blah|install)' = 'install /bin/true ' ] && \
    [ ! "$(lsmod | grep blah)" ]
) || report "1.2.4" "Ensure blah is disable" "Level 2"
```

In the extract, there are two tests, as denoted by the block of statements in parenthesis followed by the `;` control operator and a call to **report** (a function defined in the audit script) with the test identifier.  The **report** function takes up to 3 arguments.  The first two are required, they are the control number and the control title.  The third argument is optional and is only used to mark a control as a `Level 2` instead of the default `Level 1`.

#### Test Rules

The following rules must be followed to ensure that the audit.sh properly reports results:

1. The statements in a test block must not emit any output to the shell's standard output or standard error streams. If necessary, redirection operators (`>`, `2>`, `&>`) can be used to send output to `/dev/null`.
1. Any unsuccessful statement causes the test to fail.  If necessary, the control operators (`&&`, `||`, and `!`) can be used to build compound statement by providing the logical AND, OR, and NOT operators.
1. When a test block contains more than a single statement, they must either be chained together with either the `&&` or `||` control operators, otherwise the `;` control operator is assumed and command is always assumed to have succeeded with that operator.  Alternatively, if the test block contains complex logic that cannot be chained (e.g. while and for loops), an exit command must be included in the test block to report the appropriate exit status of the block.

## Audit Script

The **audit script** runs the test script and handles collecting the results.  It takes *one* or *two* argument: the name the test script to execute, and optionally a flag indicating that level 2 controls be considered as required.

The audit script will also read a set of ignored tests from the file `/tmp/exceptions` (exceptions file) if it exists and is readable.

### Output

The **audit script** outputs the result of every single test block executed.  Controls that pass are reported as `PASSED`, regardless of their level and the **CIS_LEVEL** criteria specified.  Controls that fail, are reported as `FAILED` unless one of these two situations apply:
* the **CIS_LEVEL** criteria has been set to `1` and the failing control is a level 2 control, or
* the control has been specified as an ignored control
In either of these cases, the control is reported as `SKIPPED`.

### Errors and Warnings

The audit script will issue a warning to the standard error stream and exit successfully if no test script is specified.

The audit script will issue an error to the standard error stream and exit unsuccessfully if the specified test script is not readable.  In addition to the error message, the audit script will run the stat command for the test script and send the output to the standard error stream.

### Exit Status

The audit script will exit with a successful status (`0`), if no test script was specified or if the test script was executed and each test either passed or was ignored.

The audit script will exit with an unsuccessful status (`1`), if the specified test script is not readable or if there was at least one failing test that wasn't ignored.
