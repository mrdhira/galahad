GOLANGCI_LINT_VERSION := v2.15.0
GOSEC_VERSION         := v2.29.0
GOVULNCHECK_VERSION   := v1.9.0

MODULE  := github.com/mrdhira/galahad
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)
LDFLAGS := -s -w -X $(MODULE)/internal/cli.version=$(VERSION) -X $(MODULE)/internal/cli.commit=$(COMMIT)
AGENT_LDFLAGS := -s -w -X $(MODULE)/internal/agent.version=$(VERSION) -X $(MODULE)/internal/agent.commit=$(COMMIT)

.PHONY: gate build test tools clean

gate:
	bash scripts/gate.sh

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/galahad ./cmd/galahad
	CGO_ENABLED=0 go build -trimpath -ldflags "$(AGENT_LDFLAGS)" -o bin/galahad-agent ./cmd/galahad-agent

test:
	go test -race -count=1 ./...

tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

clean:
	rm -rf bin dist
