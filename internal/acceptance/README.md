# Acceptance tests

Acceptance tests are defined used [Cucumber](https://cucumber.io/) in
[Gherkin](https://cucumber.io/docs/gherkin/) syntax, the steps are implemented
in Go with the help of [Godog](https://github.com/cucumber/godog/).

Feature files written in Gherkin are kept in the [features](../../features/)
directory.

Entry point for the tests is the [acceptance_test.go](acceptance_test.go), which
uses the established Go test to launch Godog.

## Running

To run the acceptance tests either run:

    $ make acceptance

from the root of the repository.

Or run the acceptance_test.go test using `go test`:

    $ go test ./internal/acceptance/

The latter is useful for specifying additional arguments. Currently, two are
supported:

  * `-persist` if specified the test environment will persist after test
    execution, making it easy to recreate test failures and debugg the `ec`
    command line or acceptance test code
  * `-tags=...` comma separated tags to run, e.g. `@bugs` - to run only the
    scenarios tagged with `@bugs`, or `@bugs,~@wip` to run all scenarios that
    are tagged with `@bugs` but not with `@wip`

Depending on your setup Testcontainer's ryuk container migh need to be run as
privileged container. For that, $HOME/.testcontainers.properties needs to be
created with:

    ryuk.container.privileged=true

Also, you will need to be able to run Docker without elevating the privileges,
that is as a non-root user. See the
[documentation](https://docs.docker.com/engine/install/linux-postinstall/) on
Docker website how to accomplish that.

## Creating acceptance tests

You can use the existing step implementations and add scenarios to existing or
new feature files. For any new steps Godog will print the function snippet that
needs to be implemented to support it. Please take care to refactor and extend
the functionality of existing step implementations and add new steps only when
existing steps are not sufficient. Keeping the acceptance test code well
organized and succinct/simple as it can be is the key to long term viability
and maintainablity of the acceptance tests.

Don't introduce dependencies on services not stubbed by the test environment.
We use [Testcontainers](https://www.testcontainers.org/) extensively to make
the test environment self-contained and deterministic. When using
Testcontainers, pass the `testcontainers.ContainerRequest` through
`testenv.TestContainersRequest` to make sure the `persist` flag is honored.

We use [WireMock](https://wiremock.org/) to stub HTTP APIs, such as Kuberetes
apiserver or Rekord.

Make sure not to introduce global state as this makes it difficult to run tests
concurrently. Running the acceptance tests concurrently is important for fast
feedback/turnaround. All state should be held in `context.Context`'s values.
Make sure that keys for those values are unique and package-private to prevent
dependencies from client packages on the `context.Context` state specific to
the implementation of the stub/helper.

When possible use the exact types (structs) for the API payloads and
(un)marshall to JSON/YAML at the edges of the stub. This helps with making the
payloads future-proof.

Pay attention to the `testenv.Persisted()` if the test is running whe the
`persisted` flag when cleaning up state that is needed to reproduce the test
failure.

Whenever possible include enough information in the test failure to make it
easy to reason about the context of the failure. Consider situations where
all that is available is the log output of the tests and the error message
from the test failure.
