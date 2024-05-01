# Default stubs for WireMock

This directory contains default stubs for [WireMock](https://wiremock.org).
They were created by recording the state of WireMock when run in proxy mode.

To record additional recordings run:

    $ docker run --rm \
      -p 8080:8080 \
      -e uid=$(id -u) \
      -v $PWD:/home/wiremock:Z \
      wiremock/wiremock:2.33.2 \
      --proxy-all="_THE TARGET SERVICE_" \
      --record-mappings

The recordings currently placed here include:

  * stubs for requests issued to Kubernetes apiserver using the ec command
    line tool for validating enterprise contract

# Keyless Tests

Some of the acceptance tests that cover the identity-based signatures, aka keyless, rely on
pre-recorded data. This data, which includes the TUF root, inevitably expire every 6 months.

Use the script [generate-test-signed-images.sh](/hack/generate-test-signed-images.sh) to
regenerate it. NOTE: You must use an older version of cosign, `v2.0.2` is known to work.
