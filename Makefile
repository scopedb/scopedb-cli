.PHONY: build check fmt test test-race vet clean

build:
	mkdir -p bin
	go build -trimpath -o bin/scope ./cmd/scope

check:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	go test ./...

fmt:
	gofmt -w cmd internal

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

clean:
	go clean
