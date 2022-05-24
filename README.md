# `ec` a command line client for HACBS Enterprise Contract

```
$ ec
TODO: description

Usage:
  ec [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  eval        Evaluate enterprise contract
  help        Help about any command
  version     Print version information

Flags:
  -h, --help   help for ec

Use "ec [command] --help" for more information about a command.
```

## Building

Run `make` from the root directory and use the `dist/ec` executable.

## Demo

Run `hack/demo.sh` to evaluate the policy against images that have been
built ahead of time. Or use `hack/test-builds.sh hacbs` from the
https://github.com/redhat-appstudio/build-definitions/ repository with
the Tekton Chains controller from the `poc-tep-84` branch, e.g. via the
image built here: https://github.com/hacbs-contract/chains/pkgs/container/chains%2Fcontroller/?tag=poc-tep-84
