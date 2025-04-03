# `ec` a command line client for verifying artifacts and evaluating policies

The `ec` tool is used to evaluate Conforma policies for Software
Supply Chain. Various sub-commands can be used to assert facts about an artifact
such as:
  * Validating container image signature
  * Validating container image provenance
  * Evaluating [policies][pol] over the container image provenance
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

#### **1. Go Module Checksum Mismatch Error**

When downloading dependencies, you might encounter a checksum mismatch error like this:
```
go: downloading github.com/googleapis/enterprise-certificate-proxy v0.3.3
verifying github.com/googleapis/enterprise-certificate-proxy@v0.3.3: checksum mismatch
        downloaded: h1:G6q7VHBoU74wQHXFsZSLMPl0rFw0ZDrlZ3rt6/aTBII=
        go.sum:     h1:QRje2j5GZimBzlbhGA2V2QlGNgL8G6e+wGo/+/2bWI0=
```

This issue may be resolved by running the following command to set the Go proxy, which helps resolve checksum mismatches:
``` bash
$ go env -w GOPROXY='https://proxy.golang.org,direct'
```

#### **2. Docker Container Start Failures in Acceptance Tests**

When running acceptance tests you may experience issues with starting enough Docker containers to successfully complete testing. These issues may appear as repeated failures, such as seen below, and a failed acceptance test run:
```
time="2024-03-08T09:10:50-05:00" level=warning msg="Failed, retrying in 1s ... (3/3). Error: trying to reuse blob sha256:b5976a979c30628edfeee0a1f1797362b0c84cf6cb4760776aa64ec8e3e4c2b3 at destination: pinging container registry localhost:37837: Get \"http://localhost:37837/v2/\": read tcp 127.0.0.1:34090->127.0.0.1:37837: read: connection reset by peer"
```

This issue may be resolved by increasing the total number of `fs.inotify.max_user_watches` by executing the following on: Red Hat / Fedora systems (other systems may need modifications to this)
``` bash
$ echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
```

#### **3. Apiserver and Rekor Host Resolution Failure**

Apiserver and Rekor Host Resolution Failure: While running the acceptance tests, if you encounter issues related to apiserver and rekor hosts, like:
```
+ Error: unable to fetch EnterpriseContractPolicy: Get "http://apiserver.localhost:32971/apis/appstudio.redhat.com/v1alpha1/namespaces/acceptance/enterprisecontractpolicies/mismatched-image-digest": dial tcp: lookup apiserver.localhost on 127.0.0.1:53: no such host

Post \"${REKOR}/api/v1/log/entries/retrieve\": POST ${REKOR}/api/v1/log/entries/retrieve giving up after 4 attempt(s): Post \"${REKOR}/api/v1/log/entries/retrieve\": dial tcp: lookup rekor.localhost on 127.0.0.1:53: no such host
```

This issue may be resolved by adding the below entries in the `/etc/hosts` file:
```
127.0.0.1 apiserver.localhost
127.0.0.1 rekor.localhost
```

[pol]: https://github.com/enterprise-contract/ec-policies/
[docs]: https://conforma.dev/docs/ec-cli/ec.html
