# Release Pipelines

This directory contains the Tekton Pipelines used to release EC from the main branch. These
Pipelines execute in [Konflux](https://konflux-ci.dev/).

The Pipelines are generated via [kustomize](https://kustomize.io/) from the `src` directory. To
make changes to the Pipelines, update the corresponding files in that directory and run the
`make generate-pipelines` command (requires `kustomize`).

## Why are there two Pipelines?

Currently, it is not possible to specify the EC policy in the ReleasePlan, nor any general Pipeline
parameter. Because the CLI and the Tekton Task require different EC policies, the only way to
achieve this is by using different Pipelines with different default values for the EC policy.
