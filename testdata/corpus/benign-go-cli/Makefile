.PHONY: build lint tools

build:
	go build -o bin/benign-go-cli .

lint: tools
	golangci-lint run ./...

tools:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$(go env GOPATH)/bin v2.1.0
