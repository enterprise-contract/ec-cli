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
