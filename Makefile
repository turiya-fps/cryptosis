GO        ?= go
BIN       := bin/cryptosis
FUZZTIME  ?= 10s
FUZZ_PKGS := ./internal/gpg ./internal/sanitize

.PHONY: all build test race lint vuln fuzz tidy clean

all: lint test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN) ./cmd/cryptosis

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

lint:
	golangci-lint run

vuln:
	govulncheck ./...

# Runs each Fuzz* target for FUZZTIME.
fuzz:
	@for pkg in $(FUZZ_PKGS); do \
	  for f in $$($(GO) test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
	    echo "== $$pkg $$f"; \
	    $(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
	  done; \
	done

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin dist
