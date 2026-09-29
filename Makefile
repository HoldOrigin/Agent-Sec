.PHONY: run collector sensor test test-postgres build replay agent-scenarios e2e fmt vet clean

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

test-postgres:
	@test -n "$$TEST_DATABASE_URL" || (echo "TEST_DATABASE_URL must point to a disposable database" && exit 1)
	go test -tags=integration ./internal/store

build:
	go build -trimpath -o bin/sentinel ./cmd/server
	go build -trimpath -o bin/replay ./cmd/replay
	go build -trimpath -o bin/sentinel-collector ./cmd/collector
	go build -trimpath -o bin/agent-scenario ./cmd/agent-scenario
	go build -trimpath -o bin/demo-payload ./cmd/demo-payload

replay:
	go run ./cmd/replay -reset -interval 50ms

agent-scenarios:
	go run ./cmd/agent-scenario -scenario all -mode deterministic

e2e:
	bash scripts/e2e_ebpf_ai_demo.sh

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	go clean -cache -testcache
