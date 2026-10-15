# GOPATH/GOMODCACHE/GOCACHE are intentionally left unset here. The Go
# toolchain computes sane per-user defaults on its own (rooted under
# $HOME), and any caller (CI, container, local env) that already exports
# these wins automatically since we never touch them in the recipes below.

# Install destination is fully parameterized — no environment-specific
# paths baked in. Override PREFIX and/or DESTDIR at invocation, e.g.:
#   make install PREFIX=$HOME/.local
#   make install DESTDIR=/tmp/staging PREFIX=/usr
PREFIX ?= /usr/local
DESTDIR ?=
BINDIR ?= $(DESTDIR)$(PREFIX)/bin

.PHONY: build test lint vet fmt check install live-test

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

# Builds this tree and runs the real caller shapes against an isolated serve in
# a private temporary directory (docs/LIVE-TEST.md). One JSON line per shape on
# stdout; the exit status is non-zero when any shape fails. Pass flags with
#   make live-test LIVETEST_ARGS="--runtime-cli /path/to/runtime"
LIVETEST_ARGS ?=

live-test:
	go run ./cmd/livetest $(LIVETEST_ARGS)

install:
	go build -o gatekeeper ./cmd/gatekeeper
	install -d "$(BINDIR)"
	install -m 0755 gatekeeper "$(BINDIR)/gatekeeper"
	rm -f gatekeeper
