# image-audit-tool - gcp

This page describes using this tool with Google Cloud Platform as the target cloud provider.

## Usage

### Command Line Arguments

When targetting Google Cloud Platform, the `<cloud>` argument must be `gcp`.

In Google Cloud Platform, the image identifier is its name.

### Environment Variables

For Google Cloud Platform, the **CLOUD_LOCATION** environment variable must be set to an availability zone where the Google Compute Engine Instance will be launched.

Additionally, Google Cloud Platform has a default Network named `default` where Google Compute Engine Instances can be attached. To use the default Network, simply omit setting the **VPC_IDENTIFIER** environment variable. To another Network, set the **VPC_IDENTIFIER** environment variable to the name of the Network to use.

The Google Cloud Platform also requires a project identifier to be set.  This is done with the **TF_VAR_gcp_project** environment variable.  The following argument can be used on the **docker run** command to set the environment variable:

`-e TF_VAR_gcp_project=my-project`

### Volume Mounts

When using Google Cloud Platform, a volume mount is needed to provide access to the Google Cloud Platform credentials stored on the host system.

Those credentials should be generated ahead of time using the following command:
```
$ gcloud auth application-default login
```

The credentials are stored in the `.config/gcloud` directory under the user's home directory.  That directory should be mounted to the path `/root/.config/gcloud` in the container as a read-only volume.  The following argument can be used on the **docker run** command to specify that volume mount:

`-v $HOME/.config/gcloud:/root/.config/gcloud:ro`

