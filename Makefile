MAKEFLAGS+=-j
VERSION:=$$(git log -1 --format='%H')
ALL_SUPPORTED_OS_ARCH:=$(shell go tool dist list -json|jq -r '.[] | select(.FirstClass == true and .GOARCH != "386") | "dist/ec_\(.GOOS)_\(.GOARCH)"')
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
	} BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9%/_]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", "make " $$1, ww($$2) } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development targets

.PHONY: $(ALL_SUPPORTED_OS_ARCH)
$(ALL_SUPPORTED_OS_ARCH): ## Build binaries for specific platform/architecture, e.g. make dist/ec_linux_amd64
	@GOOS=$$(echo $(notdir $@) |cut -d'_' -f2); \
	GOARCH=$$(echo $(notdir $@) |cut -d'_' -f3); \
	GOOS=$${GOOS} GOARCH=$${GOARCH} go build -ldflags="-s -w -X github.com/hacbs-contract/ec-cli/cmd.Version=$(VERSION)" -o dist/ec_$${GOOS}_$${GOARCH}; \
	sha256sum -b dist/ec_$${GOOS}_$${GOARCH} > dist/ec_$${GOOS}_$${GOARCH}.sha256

.PHONY: dist
dist: $(ALL_SUPPORTED_OS_ARCH) ## Build binaries for all supported operating systems and architectures

.PHONY: build
build: dist/ec_$(shell go env GOOS)_$(shell go env GOARCH) ## Build the ec binary for the current platform
	@ln -sf ec_$(shell go env GOOS)_$(shell go env GOARCH) dist/ec

.PHONY: test
test: ## Run unit tests
	@go test -race -covermode=atomic -coverprofile=coverage.txt -short -timeout 500ms ./...

.PHONY: acceptance
acceptance: ## Run acceptance tests
	@go test ./internal/acceptance

.PHONY: lint
lint: ## Run linter
# addlicense doesn't give us a nice explanation so we prefix it with one
	@go run github.com/google/addlicense -c $(COPY) -s -check . | sed 's/^/Missing license header in: /g'
# piping to sed above looses the exit code, luckily addlicense is fast so we invoke it for the second time to exit 1 in case of issues
	@go run github.com/google/addlicense -c $(COPY) -s -check . >/dev/null 2>&1
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint run --sort-results

.PHONY: lint-fix
lint-fix: ## Fix linting issues automagically
	@go run github.com/google/addlicense -c $(COPY) -s .
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint run --fix

.PHONY: clean
clean: ## Delete build output
	@rm dist/*
