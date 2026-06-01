GOCACHE ?= /tmp/go-cache

.PHONY: build test lint vet fmt check

build:
	GOCACHE=$(GOCACHE) go build ./...

test:
	GOCACHE=$(GOCACHE) go test ./...

lint: vet fmt

vet:
	GOCACHE=$(GOCACHE) go vet ./...

fmt:
	go fmt ./...

check: vet test
