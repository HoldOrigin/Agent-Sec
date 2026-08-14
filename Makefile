.PHONY: run collector sensor test build replay fmt vet clean

GOCACHE ?= $(CURDIR)/.cache/go-build
GOPATH ?= $(CURDIR)/.cache/gopath
export GOCACHE
export GOPATH

run:
	go run ./cmd/server

collector:
	go run ./cmd/collector

sensor:
	$(MAKE) -C sensor/ebpf

test:
	go test ./...

build:
	go build -trimpath -o bin/sentinel ./cmd/server
	go build -trimpath -o bin/replay ./cmd/replay
	go build -trimpath -o bin/sentinel-collector ./cmd/collector

replay:
	go run ./cmd/replay -reset -interval 50ms

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	go clean -cache -testcache
