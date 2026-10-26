FORGE ?= forge

.PHONY: build test lint fmt

build:
	go build ./...
	cd contracts && $(FORGE) build

test:
	go test -race ./...
	cd contracts && $(FORGE) test

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"
	cd contracts && $(FORGE) fmt --check

fmt:
	gofmt -w .
	cd contracts && $(FORGE) fmt
