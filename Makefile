MAKEFLAGS+=-j --no-print-directory
VERSION:=$$(git log -1 --format='%H')
ALL_SUPPORTED_OS_ARCH:=$(shell go tool dist list -json|jq -r '.[] | select((.FirstClass == true or .GOARCH == "ppc64le") and .GOARCH != "386") | "dist/ec_\(.GOOS)_\(.GOARCH)"')
SHELL=bash
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
COPY:="Red Hat, Inc."

##@ Information targets

.PHONY: help
help: ## Display this help.
	@awk 'function ww(s) {\
		if (length(s) < 59) {\
			return s;\
		}\
		else {\
			r="";\
			l="";\
			split(s, arr, " ");\
			for (w in arr) {\
				if (length(l " " arr[w]) > 59) {\
					r=r l "\n                     ";\
					l="";\
				}\
				l=l " " arr[w];\
			}\
			r=r l;\
			return r;\
		}\
	} BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9%/_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", "make " $$1, ww($$2) } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development targets

.PHONY: $(ALL_SUPPORTED_OS_ARCH)
$(ALL_SUPPORTED_OS_ARCH): ## Build binaries for specific platform/architecture, e.g. make dist/ec_linux_amd64
	@GOOS=$$(echo $(notdir $@) |cut -d'_' -f2); \
	GOARCH=$$(echo $(notdir $@) |cut -d'_' -f3); \
	GOOS=$${GOOS} GOARCH=$${GOARCH} go build -trimpath -ldflags="-s -w -X github.com/hacbs-contract/ec-cli/cmd.Version=$(VERSION)" -o dist/ec_$${GOOS}_$${GOARCH}; \
	sha256sum -b dist/ec_$${GOOS}_$${GOARCH} > dist/ec_$${GOOS}_$${GOARCH}.sha256

.PHONY: dist
dist: $(ALL_SUPPORTED_OS_ARCH) ## Build binaries for all supported operating systems and architectures

.PHONY: build
build: dist/ec_$(shell go env GOOS)_$(shell go env GOARCH) ## Build the ec binary for the current platform
	@ln -sf ec_$(shell go env GOOS)_$(shell go env GOARCH) dist/ec

.PHONY: reference-docs
reference-docs: ## Generate reference documentation input YAML files
	@rm -rf dist/reference
	@go run internal/documentation/documentation.go -yaml dist/reference

.PHONY: test
test: ## Run unit tests
	@go test -race -covermode=atomic -coverprofile=coverage-unit.out -timeout 500ms -tags=unit ./...
	@go test -race -covermode=atomic -coverprofile=coverage-integration.out -timeout 15s -tags=integration ./...
# Given the nature of generative tests the test timeout is increased from 500ms
# to 30s to accommodate many samples being generated and test cases being run.
	@go test -race -covermode=atomic -coverprofile=coverage-generative.out -timeout 30s -tags=generative ./...

.ONESHELL:
.SHELLFLAGS=-e -c
.PHONY: acceptance
acceptance: ## Run acceptance tests
	@ACCEPTANCE_WORKDIR="$$(mktemp -d)"
	@function cleanup() {
	  rm -rf "$${ACCEPTANCE_WORKDIR}"
	}
	@trap cleanup EXIT
	@cp -R . "$${ACCEPTANCE_WORKDIR}"
	@cd "$${ACCEPTANCE_WORKDIR}"
	@go run internal/acceptance/coverage/coverage.go .
	@$(MAKE) build
	@export COVERAGE_FILEPATH="$${ACCEPTANCE_WORKDIR}"
	@export COVERAGE_FILENAME="-acceptance"
	@go test -tags=acceptance ./...
	@go run -modfile internal/tools/go.mod github.com/wadey/gocovmerge "$${ACCEPTANCE_WORKDIR}"/coverage-acceptance*.out > "$(ROOT_DIR)/coverage-acceptance.out"

LICENSE_IGNORE=-ignore 'dist/reference/*.yaml'
LINT_TO_GITHUB_ANNOTATIONS='map(map(.)[])[][] as $$d | $$d.posn | split(":") as $$posn | "::warning file=\($$posn[0]),line=\($$posn[1]),col=\($$posn[2])::\($$d.message)"'
.PHONY: lint
lint: ## Run linter
# addlicense doesn't give us a nice explanation so we prefix it with one
	@go run -modfile internal/tools/go.mod github.com/google/addlicense -c $(COPY) -s -check $(LICENSE_IGNORE) . | sed 's/^/Missing license header in: /g'
# piping to sed above looses the exit code, luckily addlicense is fast so we invoke it for the second time to exit 1 in case of issues
	@go run -modfile internal/tools/go.mod github.com/google/addlicense -c $(COPY) -s -check $(LICENSE_IGNORE) . >/dev/null 2>&1
	@go run -modfile internal/tools/go.mod github.com/golangci/golangci-lint/cmd/golangci-lint run --sort-results $(if $(GITHUB_ACTIONS), --out-format=github-actions --timeout=5m0s)
# We don't fail on the internal (error handling) linter, we just report the
# issues for now.
# TODO: resolve the error handling issues and enable the linter failure
	@go run -modfile internal/tools/go.mod ./internal/lint $(if $(GITHUB_ACTIONS), -json) $$(go list ./... | grep -v '/internal/acceptance/') $(if $(GITHUB_ACTIONS), | jq -r $(LINT_TO_GITHUB_ANNOTATIONS))

.PHONY: lint-fix
lint-fix: ## Fix linting issues automagically
	@go run -modfile internal/tools/go.mod github.com/google/addlicense -c $(COPY) -s -ignore 'dist/reference/*.yaml' .
	@go run -modfile internal/tools/go.mod github.com/golangci/golangci-lint/cmd/golangci-lint run --fix
# We don't apply the fixes from the internal (error handling) linter.
# TODO: fix the outstanding error handling lint issues and enable the fixer
#	@go run -modfile internal/tools/go.mod ./internal/lint -fix $$(go list ./... | grep -v '/internal/acceptance/')
	@go run -modfile internal/tools/go.mod github.com/daixiang0/gci write -s standard -s default -s "prefix(github.com/hacbs-contract/ec-cli)" .

.PHONY: ci
ci: test lint-fix acceptance ## Run the usual required CI tasks

.PHONY: clean
clean: ## Delete build output
	@rm dist/*

IMAGE_TAG ?= latest
IMAGE_REPO ?= quay.io/hacbs-contract/ec-cli
.PHONY: build-image
build-image: build ## Build container image with ec-cli
	@podman build -t $(IMAGE_REPO):$(IMAGE_TAG) -f Dockerfile

.PHONY: push-image
push-image: build-image ## Push ec-cli container image to default location
	@podman push $(PODMAN_OPTS) $(IMAGE_REPO):$(IMAGE_TAG)

.PHONY: build-snapshot-image
build-snapshot-image: push-image ## Build the ec-cli image and tag it with "snapshot"
	@podman tag $(IMAGE_REPO):$(IMAGE_TAG) $(IMAGE_REPO):snapshot

.PHONY: push-snapshot-image
push-snapshot-image: build-snapshot-image ## Push the ec-cli image with the "snapshot" tag
	@podman push $(PODMAN_OPTS) $(IMAGE_REPO):snapshot

TASK_TAG ?= latest
TASK_REPO ?= quay.io/hacbs-contract/ec-task-bundle
TASK_VERSION ?= 0.1
TASK ?= task/$(TASK_VERSION)/verify-enterprise-contract.yaml
.PHONY: task-bundle
task-bundle: ## Push the Tekton Task bundle an image repository
	@go run -modfile internal/tools/go.mod github.com/tektoncd/cli/cmd/tkn bundle push $(TASK_REPO):$(TASK_TAG) -f $(TASK)
