.PHONY: build check demo fmt fmt-check race record-demo release-artifacts test vet

BIN_DIR := bin
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/byjanke/ghostlink/internal/buildinfo.Version=$(VERSION) \
	-X github.com/byjanke/ghostlink/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/byjanke/ghostlink/internal/buildinfo.Date=$(BUILD_DATE)

build:
	mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ghostlink-demo ./cmd/demo
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ghostlink-server ./cmd/server
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ghostlink-client ./cmd/client
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ghostlink-bridge ./bridge

check: fmt-check vet test race

demo:
	go run ./cmd/demo

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

fmt-check:
	@files="$$(gofmt -l .)"; if [ -n "$$files" ]; then echo "gofmt required:"; echo "$$files"; exit 1; fi

record-demo:
	vhs docs/demo.tape

release-artifacts:
	VERSION=$(VERSION) ./tools/release.sh

race:
	go test -race ./...

test:
	go test ./...

vet:
	go vet ./...
