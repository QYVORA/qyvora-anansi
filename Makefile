BINARY := anansi
VERSION ?= dev
GOFLAGS := -ldflags="-s -w -X github.com/QYVORA/qyvora-anansi-cli/cmd.Version=$(VERSION)" -trimpath
GOFLAGS_RACE := $(GOFLAGS) -race

.PHONY: all build test test-race vet lint verify clean

all: lint vet test build

build:
	go build $(GOFLAGS) -o $(BINARY) .

test:
	go test ./... -count=1 -timeout 60s

test-race:
	go test -race ./... -count=1 -timeout 120s

vet:
	go vet ./...

lint:
	golangci-lint run ./...

verify: lint vet test-race build
	@echo "ALL CHECKS PASSED"

clean:
	rm -f $(BINARY)
	rm -rf releases/
