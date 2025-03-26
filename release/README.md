# Release Pipeline

This directory contains the Tekton Pipeline used to release Conforma from the main branch. The Pipeline
executes in [Konflux](https://konflux-ci.dev/).

## Setup

The [setup.yaml](setup.yaml) file should be applied to the namespace where the release Pipeline
will run. This creates a ServiceAccount with access to perform the release.

## Why are there two verify-enterprise-contract Tasks?

The CLI and the bundle images require different Conforma policies. The bundle image, for example, does not
include binary content, as such, it makes little sense to run scan it with an anti-virus for example.
Currently, it is not possible to use a single Conforma policy for different components, but there are plans
for doing so. When that becomes a reality, a single snapshot and a single execution of the
verify-enterprise-contract would be sufficient.
