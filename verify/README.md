# image-audit-tool - Audit Scripts

This tool is designed to support any audit script that adheres to the interface specified on this page. This is done by having a master script named audit.sh which provides the reporting and handling of ignored controls, which then executes the statements contained in a specified file (test script).

## Test Scripts

The tool currently provides the following test scripts:

* `cis-ubuntu-linux-20.04-lts-benchmarks-level-1.sh` - All Level 1 Server controls from the CIS Ubuntu Linux 20.04 LTS Benchmark

### Developing Test Scripts

This section describes how the test script is structured for those interested in creating a custom test script.

#### Test Script Structure

The following extract shows the contents of a test script:

```bash
(
    grep -q 'some_value' /etc/some.file
) || report 1.2.3

(
    [ modprobe -n -v blah | grep -E '(blah|install)' = 'install /bin/true ' ]
    [ ! "$(lsmod | grep blah)" ]
) || report 1.2.4
```

In the extract, there are two tests, as denoted by the block of statements in parenthesis followed by the `||` control operator and a call to **report** (a function defined in the audit script) with the test identifier.

#### Test Rules

The following rules must be followed to ensure that the audit.sh properly reports results:

1. The statements in a test block must not emit any output to the shell's standard output or standard error streams. If necessary, redirection operators (`>`, `2>`, `&>`) can be used to send output to `/dev/null`.
1. Any unsuccessful statement causes the test to fail.  If necessary, the control operators (`&&`, `||`, and `!`) can be used to build compound statement by providing the logical AND, OR, and NOT operators.

## Audit Script

The audit script is the entrypoint to running the audit.  The script takes a single argument: a relative path to the test script to execute.

The audit script will also read a set of ignored tests from the file `/tmp/exceptions` (exceptions file) if it exists and is readable.

### Output

The only output from the execution of the audit.sh script is a list of failed tests.  Each failed test is reported on a separate line with the test identifier followed by either the word `FAILED` or `SKIPPED`.  Every failing test is reported as `FAILED` unless the test identifier appears in the exceptions file.

### Errors and Warnings

The audit script will issue a warning to the standard error stream and exit successfully if no test script is specified.

The audit script will issue an error to the standard error stream and exit unsuccessfully if the specified test script is not readable.  In addition to the error message, the audit script will run the stat command for the test script and send the output to the standard error stream.

### Exit Status

The audit script will exit with a successful status (`0`), if no test script was specified or if the test script was executed and each test either passed or was ignored.

The audit script will exit with an unsuccessful status (`1`), if the specified test script is not readable or if there was at least one failing test that wasn't ignored.
