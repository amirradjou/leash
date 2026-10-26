# Foundry installs to ~/.foundry/bin, which is not always on PATH.
export PATH := $(PATH):$(HOME)/.foundry/bin
FORGE ?= forge

.PHONY: build test test-deep mutation eval lint fmt

build:
	go build ./...
	cd contracts && $(FORGE) build

# The Go integration tests deploy the forge artifacts on Anvil, so build the contracts first.
test:
	cd contracts && $(FORGE) build
	go test -race ./...
	cd contracts && $(FORGE) test

# 10k fuzz runs per test, 1024 x 128 invariant sequences.
test-deep:
	cd contracts && FOUNDRY_PROFILE=deep $(FORGE) test

# Every seeded bug in LeashAccount must be caught by the invariant suite alone.
mutation:
	scripts/mutation-check.sh

# make eval EVAL="ollama:qwen2.5:7b:plain:3 claude-opus-5-5:plain:3"
eval:
	scripts/run-evals.sh $(EVAL)

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"
	cd contracts && $(FORGE) fmt --check

fmt:
	gofmt -w .
	cd contracts && $(FORGE) fmt
