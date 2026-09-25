.PHONY: build test

build:
	CGO_ENABLED=0 go build -o blastgate ./cmd/blastgate

test:
	go test -race -count=1 ./...
