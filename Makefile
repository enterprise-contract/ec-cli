build:
	@go build -ldflags="-s -w -X github.com/hacbs-contract/ec-cli/cmd.Version=$$(git rev-parse HEAD)" -o dist/ec

all: build
