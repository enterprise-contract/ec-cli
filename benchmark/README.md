# Benchmarks of ec CLI

Benchmarks within this directory use the [golang
benchmarking](golang.org/x/benchmarks/) package and output in the [standard
benchmark
format](https://go.googlesource.com/proposal/+/master/design/14313-benchmark-format.md).

Each benchmark is built as a standalone executable with no external dependency
other than any data that is contained within it. Benchmarks are run from within
the directory they're defined in, simply by running `go run .`, additional
arguments can be passed in, for example `-benchnum 10` to run the benchmark 10
times.
