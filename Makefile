# GOPATH/GOMODCACHE/GOCACHE are intentionally left unset here. The Go
# toolchain computes sane per-user defaults on its own (rooted under
# $HOME), and any caller (CI, container, local env) that already exports
# these wins automatically since we never touch them in the recipes below.
.PHONY: build test lint vet fmt check

build:
	go build ./...

test:
	go test ./...

lint: vet fmt

vet:
	go vet ./...

fmt:
	go fmt ./...

check: vet test
