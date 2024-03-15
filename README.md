# `ec` a command line client for evaluating the Enterprise Contract

The `ec` tool is used to evaluate Enterprise Contract policies for Software
Supply Chain. Various sub-commands can be used to assert facts about an artifact
such as:
  * Validating container image signature
  * Validating container image provenance
  * Evaluating Enterprise Contract [policies][pol] over the container image provenance
  * Fetching artifact authorization

Consult the [documentation][docs] for available sub-commands, descriptions and
examples of use.

## Building

Run `make build` from the root directory and use the `dist/ec` executable, or
run `make dist` to build for all supported architectures.

## Testing

Run `make test` to run the unit tests, and `make acceptance` to run the
acceptance tests.

## Linting

Run `make lint` to check for linting issues, and `make lint-fix` to fix linting
issues (formatting, import order, ...).

## Demo

Run `hack/demo.sh` to evaluate the policy against images that have been
built ahead of time.

To regenerate those images, say in case of change in the attestation data, run
`hack/rebuild.sh`.

## Troubleshooting

The `--debug` parameter enables debug logging. Setting `EC_DEBUG` environment
variable can be set to prevent deletion of temporary `ec-work-*` directories so
that the attestations, policy and data files can be examined.

When running acceptance tests you may experience issues with starting enough Docker containers to successfullyl complete testing. These issues may appear as repeated failures, such as seen below, and a failed acceptance test run:
```
time="2024-03-08T09:10:50-05:00" level=warning msg="Failed, retrying in 1s ... (3/3). Error: trying to reuse blob sha256:b5976a979c30628edfeee0a1f1797362b0c84cf6cb4760776aa64ec8e3e4c2b3 at destination: pinging container registry localhost:37837: Get \"http://localhost:37837/v2/\": read tcp 127.0.0.1:34090->127.0.0.1:37837: read: connection reset by peer"
```

This issue may be resolved by increasing the total number of `fs.inotify.max_user_watches` by executing the following on: Red Hat / Fedora systems (other systems may need modifications to this)
``` bash
$ echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
```


[pol]: https://github.com/enterprise-contract/ec-policies/
[docs]: https://enterprisecontract.dev/docs/ec-cli/main/ec.html
