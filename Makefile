APP := chronopacket
BUILD_DIR := bin

.PHONY: all build test lint fmt clean

all: test build

build:
	go build -trimpath -o $(BUILD_DIR)/$(APP) ./cmd/chronopacket

test:
	go test ./...

fmt:
	test -z "$$(gofmt -l .)"

lint:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)
