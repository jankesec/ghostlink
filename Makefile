.PHONY: build check demo fmt fmt-check race record-demo test vet

BIN_DIR := bin

build:
	mkdir -p $(BIN_DIR)
	go build -trimpath -o $(BIN_DIR)/ghostlink-demo ./cmd/demo
	go build -trimpath -o $(BIN_DIR)/ghostlink-server ./cmd/server
	go build -trimpath -o $(BIN_DIR)/ghostlink-client ./cmd/client
	go build -trimpath -o $(BIN_DIR)/ghostlink-bridge ./bridge

check: fmt-check vet test race

demo:
	go run ./cmd/demo

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

fmt-check:
	@files="$$(gofmt -l .)"; if [ -n "$$files" ]; then echo "gofmt required:"; echo "$$files"; exit 1; fi

record-demo:
	vhs docs/demo.tape

race:
	go test -race ./...

test:
	go test ./...

vet:
	go vet ./...
