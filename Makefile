SHELL=/bin/bash -o pipefail

# .DEFAULT_GOAL := quickstart

.bin/golangci-lint: Makefile
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b .bin v1.50.1

.PHONY: lint
lint: .bin/golangci-lint
	GOROOT=`go env GOROOT` golangci-lint run -v ./...
