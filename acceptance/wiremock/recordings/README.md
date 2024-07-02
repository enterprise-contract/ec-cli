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
pre-recorded data. Some of this data, i.e. the TUF root, inevitably expires every 6 months.

Use the script [update-tuf-root-recordings.sh](/hack/update-tuf-root-recordings.sh) to update the
TUF root information. This should be enough to update the data that expires.

If needed, use the script [generate-test-signed-images.sh](/hack/generate-test-signed-images.sh) to
regenerate all of the data. When doing this, you may have to update the identity and issuer
expected in the tests and the `generate-test-signed-images.sh` script.
