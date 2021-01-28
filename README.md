# image-audit-tool

This tool is used to audit a cloud provider machine image for compliance with an audit script.

The tool is dockerized to offer a sleek frictionless experience to validate machine images.

## How it Works

The tool uses [Terraform](https://terraform.io/) to launch a virtual instance in the specified cloud provider using the specified image candidate.  Once the virtual instance is running, the audit script and a set of ignored controls are uploaded to the virtual instance.  The audit script (described below) is executed and every failing control is recorded as either **FAILED** or **SKIPPED** (if the control was specified as an ignored control).  Once the audit script execution has completed, Terraform is used to destroy the provisioned virtual instance.

## Audit Script

Currently, the tool only offers the CIS Ubuntu Linux 20.04 LTS Benchmark as an audit script. The design of the tool could easily be modified to support different audit scripts.

The audit script executes a series of tests organized as controls.  When the tests of a control all pass, no output is produced. When a test in a control fails, the control is marked as **FAILED** or **SKIPPED** if that control was marked as an ignored control in the exceptions file.

## Exceptions

The tested image is most likely not able to meet every single control in the audit script. A set of control numbers to ignore can be specified when invoking the tool. 

## Supported Platforms

The tool is designed to support a variety of cloud providers.

Currently, Google Cloud Platform is the only supported cloud provider. Amazon Web Services and Microsoft Azure are slated as the next providers to be added.

Usage information for supported cloud providers is further documented in cloud provider specific READMEs.

* [gcp](./terraform/gcp/README.md) - Google Cloud Platform
* [aws](./terraform/aws/README.md) - Amazon Web Services

## Usage

The tool is designed to operate in the same manner regardless of the target cloud provider by abstracting most of the details that apply across each of the cloud providers into platform agnostic parameters.  Configuration details specific to a particular cloud provider are easily specified using environment variables set in the Docker container where the tool runs.

### Command Arguments

The following two command arguments must always be provided regardless of the target cloud provider:

* `<cloud>` - The canonical name of the cloud provider
* `<image_identifier>` - The unique identifier for the machine image being tested
8 `<ignored_controls>` - (Optional) A comma-separated list of control numbers to ignore failures

### Environment Variables

The following two environment variables are recognized regardless of the target cloud provider (see cloud provider specific README page for additional details):

* `CLOUD_LOCATION` - The name of the location where the virtual instance is launched
* `VPC_IDENTIFIER` - The unique identifier for the Virtual Private Cloud network where the virtual instance is attached.  This variable is optional for some cloud providers.

Some cloud providers may require additional environment variables in the form **TF_VAR_*name***.  The cloud provider specific README page will describe these.

### Volume Mounts

When using the tool with some cloud providers, additional files from the host system are needed. In order to provide access to those files, their parent directory must be mounted as a volume into the Docker container. Refer to the cloud provider specific README page for details.

### Docker Command

As previously mentioned, this tool must be run in a Docker container.  That can be done with the following command:

```
$ docker run -it --rm -v $HOME/.config/gcloud:/root/.config/gcloud:ro -e CLOUD_LOCATION=us-central1-a -e TF_VAR_gcp_project=my-gcp-project marcboudreau/image-audit-tool:0.1.0 gcp my-image 1.1.1,2.2.2
```

Disecting the above command, we find...
* `docker run` - Creates a Docker container and starts it
* `-it` - Allocates a pseudo-TTY and keeps STDIN open even if it's not attached
* `--rm` - Automatically removes the container after it is stopped
* `-v $HOME/.config/gcloud:/root/.config/gcloud:ro` - Mounts the host's `$HOME/.config/gcloud` directory as a read-only volume in the container at `/root/.config/gcloud`
* `-e CLOUD_LOCATION=us-central1-a` - Sets the value `us-central1-a` to the environment variable `CLOUD_LOCATION` in the container
* `-e TF_VAR_gcp_project=my-gcp-project` - Sets the value `my-gcp-project` to the environment variable `TF_VAR_gcp_project` in the container
* `marcboudreau/image-audit-tool:0.1.0` - Specifies the Docker image to use for the container
* `gcp` - The target cloud provider
* `my-image` - The unique image identifier
* `1.1.1,2.2.2` - The set of controls to ignore: 1.1.1 and 2.2.2
