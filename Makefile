GOPATH     ?= /root/go
GOMODCACHE ?= $(GOPATH)/pkg/mod
GOCACHE    ?= /root/.cache/go
GOENV      := GOPATH=$(GOPATH) GOMODCACHE=$(GOMODCACHE) GOCACHE=$(GOCACHE)

.PHONY: build test lint vet fmt check

build:
	$(GOENV) go build ./...

test:
	$(GOENV) go test ./...

lint: vet fmt

vet:
	$(GOENV) go vet ./...

fmt:
	$(GOENV) go fmt ./...

check: vet test
