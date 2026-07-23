# xdpfilter — build the embedded BPF object, the static Go binary, and the .deb.
#
# Requires (build host / Lima VM only): clang, llvm, libbpf-dev, linux-libc-dev,
# golang-go, and nfpm (go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest).
# The produced binary and .deb need none of these on the target.

VERSION ?= 0.1.0
BINDIR  := dist
BIN     := $(BINDIR)/xdpfilter
GOFLAGS := -trimpath

.PHONY: all generate build dev deb clean fmt vet test

all: build

## generate: compile bpf/filter.bpf.c and embed it (bpf2go)
generate:
	go generate ./...

## build: static amd64 binary (the ship target)
build: generate
	mkdir -p $(BINDIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) \
		-ldflags "-s -w -X main.version=$(VERSION)" \
		-o $(BIN) ./cmd/xdpfilter
	@file $(BIN) || true

## dev: native-arch binary for in-VM functional tests
dev: generate
	mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build $(GOFLAGS) \
		-ldflags "-X main.version=$(VERSION)-dev" \
		-o $(BIN) ./cmd/xdpfilter

## deb: build the Debian 13 package (depends on build)
deb: build
	VERSION=$(VERSION) nfpm pkg --packager deb -f packaging/nfpm.yaml \
		-t xdpfilter_$(VERSION)_amd64.deb
	@ls -l xdpfilter_$(VERSION)_amd64.deb

## test: run the netns/veth functional harness (root)
test: dev
	sudo ./test/harness.sh

fmt:
	gofmt -w .

vet:
	CGO_ENABLED=0 GOOS=linux go vet ./...

clean:
	rm -rf $(BINDIR) *.deb \
		internal/dataplane/filter_bpfel.* internal/dataplane/filter_bpfeb.*
