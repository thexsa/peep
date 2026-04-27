VERSION := $(shell git describe --tags --always 2>/dev/null | sed 's/^v//' || echo "dev")
BINARY  := peep
LDFLAGS := -s -w -X github.com/thexsa/peep/internal/cli.Version=$(VERSION)

.PHONY: build build-all test clean

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/peep

build-all:
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64   go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64       ./cmd/peep
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64   go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64       ./cmd/peep
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64   go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64        ./cmd/peep
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64   go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64        ./cmd/peep
	CGO_ENABLED=0 GOOS=linux   GOARCH=ppc64le go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-ppc64le      ./cmd/peep
	CGO_ENABLED=0 GOOS=aix     GOARCH=ppc64   go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-aix-ppc64          ./cmd/peep
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64   go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe  ./cmd/peep

test:
	go test ./...

clean:
	rm -f $(BINARY)
	rm -rf dist/
