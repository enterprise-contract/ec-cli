MAKEFLAGS+=-j
VERSION:=$$(git log -1 --format='%H')

##@ Information targets

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
	} BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9%-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", "make " $$1, ww($$2) } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development targets

build-%:: ## Build binaries for specific platform/architecture, e.g. make build-linux-amd64
	@GOOS=$$(echo $* |cut -d'-' -f1); \
	GOARCH=$$(echo $* |cut -d'-' -f2); \
	GOOS=$${GOOS} GOARCH=$${GOARCH} go build -ldflags="-s -w -X github.com/hacbs-contract/ec-cli/cmd.Version=$(VERSION)" -o dist/ec_$${GOOS}_$${GOARCH}; \
	sha256sum -b dist/ec_$${GOOS}_$${GOARCH} > dist/ec_$${GOOS}_$${GOARCH}.sha256

build: build-linux-amd64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64 ## Build binaries for all supported operating systems and architectures

clean: ## Delete build output
	@rm dist/*

.PHONY: build clean help
