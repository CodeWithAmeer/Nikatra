BINARY=nikatra

.PHONY: build test selftest fmt clean

build:
	go build -o $(BINARY) ./cmd/nikatra

test:
	go test ./...

selftest:
	go run ./cmd/nikatra --self-test

fmt:
	gofmt -w ./cmd/nikatra

clean:
	rm -f $(BINARY) $(BINARY).exe
