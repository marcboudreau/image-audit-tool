# image-audit-tool

This tool is used to audit a cloud provider machine image for compliance with an audit script.

The tool is dockerized to offer a sleek frictionless experience to validate machine images.

## How it Works

The tool uses [Terraform](https://terraform.io/) to launch a virtual instance in the corresponding cloud provider using the specified image candidate.  Once the virtual instance is running, the audit script and a set of ignored controls are uploaded to the virtual instance.  The audit script (described below) is executed and every failing control is recorded as either **FAILED** or **SKIPPED** (if the control was specified as an ignored control).  Once the audit script execution has completed, Terraform is used to destroy the provisioned virtual instance.

## Audit Script

Currently, the tool only offers the CIS Ubuntu Linux 20.04 LTS Benchmark as an audit script. The design of the tool could easily be modified to support different audit scripts.

The audit script executes a series of tests organized as controls.  When the tests of a control all pass, no output is produced. When a test in a control fails, the control is marked as **FAILED** or **SKIPPED** if that control was marked as an ignored control in the exceptions file.

## Exceptions

The tested image is most likely not able to meet every single control in the audit script. The exception file provides the ability to mark specific controls as ignored controls. An image is considered as having passed the audit if all controls either passed or were skipped (*i.e. no controls were marked as **FAILED***).

The exceptions file is a JSON encoded document with the following structure:

```json
{
    "control_number": "justification statement"
}
```

Each key in the top-level object is a control number that will be ignored in the audit script.  The value associated with that key is simply a justification of why the control is being ignored.  The justification statement is not used by this tool.

The exceptions file must be mounted as a volume into the container.  See the **Volume Mounts** section below.

## Supported Platforms

The tool is designed to support a variety of cloud providers.

Currently, Google Cloud Platform is the only supported cloud provider. Amazon Web Services and Microsoft Azure are slated as the next providers to be added.

Usage information for supported cloud providers is further documented in cloud provider specific READMEs.

* [gcp](./terraform/gcp/README.md) - Google Cloud Platform

## Usage

The tool is designed to operate in the same manner regardless of the target cloud provider by abstracting most of the details that apply across each of the cloud providers into platform agnostic parameters.  Configuration details specific to a particular cloud provider are easily specified using environment variables set in the Docker container where the tool runs.

### Command Arguments

The following two command arguments must always be provided regardless of the target cloud provider:

* `<cloud>` - The canonical name of the cloud provider
* `<image_identifier>` - The unique identifier for the machine image being tested

### Environment Variables

The following two environment variables are recognized regardless of the target cloud provider (see cloud provider specific README page for additional details):

* `CLOUD_LOCATION` - The name of the location where the virtual instance is launched
* `VPC_IDENTIFIER` - The unique identifier for the Virtual Private Cloud network where the virtual instance is attached.  This variable is optional for some cloud providers.

Some cloud providers may require additional environment variables in the form **TF_VAR_*name***.  The cloud provider specific README page will describe these.

### Volume Mounts

The tool also requires access to various directories on the host system.  In order to provide access to those directories, they must be mounted as volumes into the Docker container.

Regardless of target cloud provider, an exceptions file must be mounted to the path `/verify/exceptions/exceptions.json` inside the Docker container.

Some cloud providers may require additional volumes to provide credentials needed to launch and destroy the virtual instance.  Refer to the cloud provider specific README page for details.

### Docker Command

As previously mentioned, this tool must be run in a Docker container.  That can be done with the following command:

```
$ docker run -it --rm -v $HOME/.config/gcloud:/root/.config/gcloud:ro -v $HOME/image/exceptions.json:/verify/exceptions/exceptions.json:ro -e CLOUD_LOCATION=us-central1-a -e TF_VAR_gcp_project=my-gcp-project marcboudreau/image-audit-tool:0.1.0 gcp my-image
```

Disecting the above command, we find...
* `docker run` - Creates a Docker container and starts it
* `-it` - Allocates a pseudo-TTY and keeps STDIN open even if it's not attached
* `--rm` - Automatically removes the container after it is stopped
* `-v $HOME/.config/gcloud:/root/.config/gcloud:ro` - Mounts the host's `$HOME/.config/gcloud` directory as a read-only volume in the container at `/root/.config/gcloud`
* `-v $HOME/image/exceptions.json:/mnt/exceptions.json:ro` - Mounts the host's `$HOME/image/exceptions.json` file as a read-only volume in the container at `/mnt/exceptions.json`
* `-e CLOUD_LOCATION=us-central1-a` - Sets the value `us-central1-a` to the environment variable `CLOUD_LOCATION` in the container
* `-e TF_VAR_gcp_project=my-gcp-project` - Sets the value `my-gcp-project` to the environment variable `TF_VAR_gcp_project` in the container
* `marcboudreau/image-audit-tool:0.1.0` - Specifies the Docker image to use for the container
* `gcp` - The target cloud provider
* `my-image` - The unique image identifier
